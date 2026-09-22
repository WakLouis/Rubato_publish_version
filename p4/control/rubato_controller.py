#!/usr/bin/env python3
from __future__ import print_function

import argparse
from collections import namedtuple
import ipaddress
import json
import logging
import math
import os
import signal
import threading
import subprocess
import sys
import tempfile
import time

try:
    from .behavior import classify_windows
    from .hardware_policy import ACTIVE, DRAINING, PREPARING, load_hardware_policy
    from .aligned_runtime import AlignedRuntime
    from .ingress_observer import DigestReceiver, WireObservation
    from .video_identity import VideoIdentities
except (ImportError, ValueError, SystemError):  # direct script execution on Python 3.5 SDE hosts
    from behavior import classify_windows
    from hardware_policy import ACTIVE, DRAINING, PREPARING, load_hardware_policy
    from aligned_runtime import AlignedRuntime
    from ingress_observer import DigestReceiver, WireObservation
    from video_identity import VideoIdentities

try:
    import yaml
except Exception:  # pragma: no cover - optional on SDE hosts
    yaml = None

try:
    from queue import Empty, Queue
except ImportError:  # pragma: no cover - Python 2 fallback for old SDE shells
    from Queue import Empty, Queue

try:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from socketserver import ThreadingMixIn
except ImportError:  # pragma: no cover
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from SocketServer import ThreadingMixIn


LOG = logging.getLogger("rubato")
FlowKey = namedtuple("FlowKey", "ip_version src_ip dst_ip src_port dst_port protocol")


class CandidateState(object):
    def __init__(self, flow, hash0, hash1, platform_id, now):
        self.flow = flow
        self.hash0 = int(hash0)
        self.hash1 = int(hash1)
        self.platform_id = int(platform_id)
        self.first_seen = now
        self.last_seen = now
        self.windows = []
        self.last_decision = None


class QueueControlState(object):
    def __init__(self, initial_rate_kbps):
        self.current_rate_kbps = int(initial_rate_kbps or 0)
        self.shaping_enabled = self.current_rate_kbps > 0
        self.last_egress_bytes = None
        self.last_q_count_cells = None
        self.last_time = None
        self.input_rate_kbps = 0.0
        self.current_q_count_cells = 0


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class DnsShadowHttpHandler(BaseHTTPRequestHandler):
    controller = None

    def log_message(self, fmt, *args):
        LOG.debug("dns-shadow-http %s", fmt % args)

    def send_json(self, status, payload):
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, {"ok": True})
            return
        self.send_json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        if self.path != "/dns-shadow":
            self.send_json(404, {"ok": False, "error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            records = payload.get("records", [])
            accepted = 0
            for record in records:
                hostname = normalize_hostname(record.get("hostname", ""))
                ip_text = str(record.get("ip", "")).strip()
                if not hostname or not ip_text:
                    continue
                self.controller.enqueue_dns_shadow_record(
                    hostname,
                    ip_text,
                    record.get("platform_id"),
                    payload.get("source", "http"),
                    record.get("ttl_s", 60),
                )
                accepted += 1
            self.send_json(200, {"ok": True, "accepted": accepted})
        except Exception as exc:
            LOG.warning("invalid DNS-shadow HTTP payload: %s", exc)
            self.send_json(400, {"ok": False, "error": str(exc)})


def load_config(path):
    with open(path, "r") as f:
        text = f.read()
    if yaml is not None:
        return yaml.safe_load(text)
    return json.loads(text)


def normalize_hostname(hostname):
    return str(hostname).strip().lower().rstrip(".")


def ip_key_value(ip_text):
    return int(ipaddress.ip_address(ip_text))


class StrongMediaRules(object):
    def __init__(self, config):
        self.suffixes = tuple(
            normalize_hostname(v) for v in config.get("strong_media_suffixes", [])
        )
        self.exact_hosts = set(
            normalize_hostname(v) for v in config.get("strong_media_exact_hosts", [])
        )
        self.embedded = tuple(
            normalize_hostname(v).strip(".") for v in config.get("embedded_strong_markers", [])
        )
        self.platform_ids = config.get("platform_ids", {})

    def match(self, hostname):
        host = normalize_hostname(hostname)
        if not host:
            return False, 0
        if host in self.exact_hosts:
            return True, self.platform_id(host)
        for marker in self.embedded:
            if marker and ".%s." % marker in ".%s." % host:
                return True, self.platform_id(marker)
        for suffix in self.suffixes:
            if host == suffix or host.endswith("." + suffix):
                return True, self.platform_id(suffix)
        return False, 0

    def platform_id(self, hostname):
        host = normalize_hostname(hostname)
        if "bilivideo" in host or "acgvideo" in host or "bili" in host:
            return int(self.platform_ids.get("bilibili", 1))
        if "googlevideo" in host:
            return int(self.platform_ids.get("youtube", 2))
        if "nflxvideo" in host:
            return int(self.platform_ids.get("netflix", 3))
        return int(self.platform_ids.get("unknown", 0))


class DnsParser(object):
    TYPE_A = 1
    TYPE_CNAME = 5
    TYPE_AAAA = 28

    def parse_response(self, payload, include_ttl=False):
        if len(payload) < 12:
            return []
        flags = int_from_bytes(payload[2:4])
        if (flags & 0x8000) == 0:
            return []
        qdcount = int_from_bytes(payload[4:6])
        ancount = int_from_bytes(payload[6:8])
        nscount = int_from_bytes(payload[8:10])
        arcount = int_from_bytes(payload[10:12])

        pos = 12
        aliases = {}
        alias_ttls = []
        results = []
        for _ in range(qdcount):
            _, pos = self._read_name(payload, pos)
            pos += 4
        for _ in range(ancount + nscount + arcount):
            name, pos = self._read_name(payload, pos)
            if pos + 10 > len(payload):
                break
            rr_type = int_from_bytes(payload[pos : pos + 2])
            ttl = int_from_bytes(payload[pos + 4 : pos + 8])
            rdlen = int_from_bytes(payload[pos + 8 : pos + 10])
            rdata_pos = pos + 10
            pos = rdata_pos + rdlen
            if pos > len(payload):
                break
            if rr_type == self.TYPE_CNAME:
                cname, _ = self._read_name(payload, rdata_pos)
                aliases[name] = cname
                alias_ttls.append(ttl)
            elif rr_type == self.TYPE_A and rdlen == 4:
                results.append((name, str(ipaddress.IPv4Address(payload[rdata_pos:pos])), ttl))
            elif rr_type == self.TYPE_AAAA and rdlen == 16:
                results.append((name, str(ipaddress.IPv6Address(payload[rdata_pos:pos])), ttl))

        expanded = []
        for name, ip_text, ttl in results:
            for related in self._related_names(name, aliases):
                effective_ttl = min([ttl] + alias_ttls)
                expanded.append(
                    (related, ip_text, effective_ttl) if include_ttl else (related, ip_text)
                )
        return expanded

    def _read_name(self, payload, pos):
        labels = []
        start = pos
        jumped = False
        seen = 0
        while pos < len(payload):
            length = byte_value(payload[pos])
            if length == 0:
                pos += 1
                break
            if length & 0xC0 == 0xC0:
                if pos + 1 >= len(payload):
                    break
                pointer = ((length & 0x3F) << 8) | byte_value(payload[pos + 1])
                if not jumped:
                    start = pos + 2
                pos = pointer
                jumped = True
                seen += 1
                if seen > 16:
                    break
                continue
            pos += 1
            labels.append(payload[pos : pos + length].decode("ascii", "ignore"))
            pos += length
        if jumped:
            return normalize_hostname(".".join(labels)), start
        return normalize_hostname(".".join(labels)), pos

    def _related_names(self, name, aliases):
        related = set([normalize_hostname(name)])
        cursor = normalize_hostname(name)
        for _ in range(8):
            nxt = aliases.get(cursor)
            if not nxt:
                break
            nxt = normalize_hostname(nxt)
            related.add(nxt)
            cursor = nxt
        for alias, target in aliases.items():
            if normalize_hostname(target) in related:
                related.add(normalize_hostname(alias))
        return related


def byte_value(value):
    if isinstance(value, int):
        return value
    return ord(value)


def int_from_bytes(value):
    result = 0
    for item in bytearray(value):
        result = (result << 8) | int(item)
    return result


class RubatoController(object):
    def __init__(self, config, args):
        if config.get("online_dbsp", {}).get("enabled", False) and args.policy:
            raise ValueError("online DBSP and legacy --policy are mutually exclusive")
        self.config = config
        self.args = args
        self.rules = StrongMediaRules(config)
        self.dns_parser = DnsParser()
        self.candidates = {}
        self.confirmed_flows = set()
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        identity_path = os.path.join(
            root, config.get("video_identity_file", "state/confirmed_video_ips.json")
        )
        self.video_identities = VideoIdentities(None if args.dry_run else identity_path)
        self.rejected_flows = {}
        self.active_bank = 0
        self.gc = None
        self.interface = None
        self.bfrt_info = None
        self.target = None
        self.table_cache = {}
        self.tm_client = None
        self.tm_transport = None
        self.queue_states = {}
        self.warned_no_video_counter = False
        self.dns_shadow_queue = Queue()
        self.dns_shadow_seen = {}
        self.dns_shadow_httpd = None
        self.dns_shadow_thread = None
        self.loop_failures = {}
        self.register_read_failures = {}
        self.register_write_failures = {}
        self.hardware_policy = load_hardware_policy(args.policy) if args.policy else None
        self.policy_active = False
        self.policy_flow_keys = []
        self.flow_policy_cache = set()
        self.aligned = (
            AlignedRuntime(self) if config.get("online_dbsp", {}).get("enabled", False) else None
        )
        self.epoch_started = time.time()
        self.epoch_ended = None
        self.cms_snapshot = None
        self.cms_bank_ready = [False, False]
        self.watchdog = None
        self.digest_receiver = None
        self.wire_observer = None
        self.stop_requested = threading.Event()

    def connect(self):
        if self.args.dry_run:
            LOG.info("dry-run mode: BFRT connection skipped")
            return
        import bfrt_grpc.client as gc

        self.gc = gc
        grpc_addr = self.config.get("grpc_addr", "localhost:50052")
        client_id = int(self.config.get("client_id", 0))
        device_id = int(self.config.get("device_id", 0))
        bind = bool(self.config.get("bfrt_bind", True))
        self.interface = gc.ClientInterface(
            grpc_addr, client_id=client_id, device_id=device_id, perform_subscribe=bind
        )
        if bind:
            self.interface.bind_pipeline_config(self.args.program_name)
        self.bfrt_info = self.interface.bfrt_info_get(self.args.program_name)
        self.target = gc.Target(device_id=device_id, pipe_id=0xFFFF)
        LOG.info("connected to BFRT program %s at %s", self.args.program_name, grpc_addr)

    def tm_backend(self):
        return str(self.config.get("tm", {}).get("backend", "thrift")).lower()

    def connect_tm(self):
        if self.tm_client is not None:
            return
        if self.args.dry_run:
            return
        tm_cfg = self.config.get("tm", {})
        from thrift.transport import TSocket, TTransport
        from thrift.protocol import TBinaryProtocol, TMultiplexedProtocol
        from tm_api_rpc import tm

        host = str(tm_cfg.get("thrift_host", "localhost"))
        port = int(tm_cfg.get("thrift_port", 9090))
        socket = TSocket.TSocket(host, port)
        socket.setTimeout(2000)
        transport = TTransport.TBufferedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        tm_protocol = TMultiplexedProtocol.TMultiplexedProtocol(protocol, "tm")
        self.tm_client = tm.Client(tm_protocol)
        self.tm_transport = transport
        self.tm_transport.open()
        LOG.info("connected to TM thrift service at %s:%d", host, port)

    def dns_shadow_listen(self):
        value = self.args.dns_shadow_listen
        if value is None:
            server_cfg = self.config.get("dns_shadow_server", {})
            if not bool(server_cfg.get("enabled", True)):
                return None
            value = str(server_cfg.get("listen", "0.0.0.0:18080"))
        if not value:
            return None
        if ":" not in value:
            return value, 18080
        host, port_text = value.rsplit(":", 1)
        return host or "0.0.0.0", int(port_text)

    def start_dns_shadow_server(self):
        if self.args.disable_dns_shadow_server or self.args.dry_run:
            return
        listen = self.dns_shadow_listen()
        if listen is None:
            return
        host, port = listen
        handler = type("RubatoDnsShadowHttpHandler", (DnsShadowHttpHandler,), {})
        handler.controller = self
        try:
            self.dns_shadow_httpd = ThreadedHTTPServer((host, port), handler)
            self.dns_shadow_thread = threading.Thread(target=self.dns_shadow_httpd.serve_forever)
            self.dns_shadow_thread.daemon = True
            self.dns_shadow_thread.start()
            LOG.info("DNS-shadow HTTP server listening on %s:%d", host, port)
        except Exception as exc:
            LOG.warning("DNS-shadow HTTP server not started on %s:%d: %s", host, port, exc)

    def enqueue_dns_shadow_record(self, hostname, ip_text, platform_id=None, source="", ttl_s=60):
        ttl_s = float(ttl_s)
        if not math.isfinite(ttl_s) or ttl_s < 0:
            raise ValueError("DNS TTL must be finite and nonnegative")
        self.dns_shadow_queue.put(
            {
                "hostname": normalize_hostname(hostname),
                "ip": str(ip_text).strip(),
                "platform_id": platform_id,
                "source": str(source or ""),
                "expires_at": time.time() + min(ttl_s, 3600),
            }
        )

    def process_dns_shadow_records(self, max_records=256):
        processed = 0
        while processed < max_records:
            try:
                record = self.dns_shadow_queue.get_nowait()
            except Empty:
                break
            processed += 1
            hostname = normalize_hostname(record.get("hostname", ""))
            ip_text = str(record.get("ip", "")).strip()
            try:
                ip_obj = ipaddress.ip_address(ip_text)
            except Exception:
                LOG.debug("ignored DNS-shadow record with invalid IP: %s", record)
                continue

            matched, platform_id = self.rules.match(hostname)
            supplied = record.get("platform_id")
            if supplied is not None and int(supplied) != platform_id:
                matched = False
            if not matched:
                LOG.debug("ignored DNS-shadow non-media record %s -> %s", hostname, ip_obj)
                continue

            key = (str(ip_obj), int(platform_id))
            if record["expires_at"] <= time.time():
                continue
            static_ips = {
                str(item["ip"])
                for version in ("ipv4", "ipv6")
                for item in self.config.get("static_media_ips", {}).get(version, [])
            }
            if str(ip_obj) in static_ips:
                continue
            if key in self.dns_shadow_seen:
                self.dns_shadow_seen[key] = max(self.dns_shadow_seen[key], record["expires_at"])
                continue
            try:
                self.dns_shadow_seen[key] = record["expires_at"]
                self.refresh_shadow_ip(str(ip_obj))
                LOG.info(
                    "DNS-shadow installed %s -> %s platform=%s source=%s",
                    hostname,
                    ip_obj,
                    platform_id,
                    record.get("source", ""),
                )
            except Exception as exc:
                self.dns_shadow_seen.pop(key, None)
                LOG.warning(
                    "failed to install DNS-shadow record %s -> %s: %s", hostname, ip_obj, exc
                )

    def refresh_shadow_ip(self, ip_text):
        if ip_text in self.video_identities.ips:
            self.install_video_identity(ip_text)
            return
        active = {
            platform
            for (ip, platform), expiry in self.dns_shadow_seen.items()
            if ip == ip_text and expiry > time.time()
        }
        if active:
            self.add_media_ip(ip_text, next(iter(active)) if len(active) == 1 else 0)
        else:
            ip = ipaddress.ip_address(ip_text)
            name = "td_ip4_exact" if ip.version == 4 else "td_ip6_exact"
            field = "hdr.ipv4.src_addr" if ip.version == 4 else "hdr.ipv6.src_addr"
            if not self.args.dry_run:
                self.delete_table_entry(name, [self.gc.KeyTuple(field, int(ip))])

    def expire_shadow_ips(self):
        expired = {ip for (ip, _), expiry in self.dns_shadow_seen.items() if expiry <= time.time()}
        for ip in expired:
            self.refresh_shadow_ip(ip)
        self.dns_shadow_seen = {
            key: expiry for key, expiry in self.dns_shadow_seen.items() if expiry > time.time()
        }

    def device_id(self):
        return int(self.config.get("device_id", 0))

    def maybe_install_ports(self):
        if self.aligned is not None:
            return  # The aligned path uses checked BFRT port writes after connect().
        ports = self.config.get("ports", {})
        enabled = bool(ports.get("enabled", False)) or self.args.install_ports
        if self.args.skip_port_init or not enabled:
            return
        commands = ports.get("commands", [])
        if not commands:
            return
        if self.args.dry_run:
            LOG.info("dry-run port init commands: %s", commands)
            return
        script_path = self.write_bfshell_command_file(commands)
        try:
            sde = os.environ.get("SDE", os.path.expanduser("~/bf-sde-link"))
            bfshell = ports.get("bfshell") or os.path.join(sde, "run_bfshell.sh")
            try:
                subprocess.check_call([bfshell, "-f", script_path])
                LOG.info("installed switch port configuration through bfshell")
            except subprocess.CalledProcessError as exc:
                if bool(ports.get("fail_on_error", False)):
                    raise
                LOG.warning("bfshell port init failed with rc=%s; continuing", exc.returncode)
        finally:
            try:
                os.unlink(script_path)
            except Exception:
                pass

    def write_bfshell_command_file(self, commands):
        fd, path = tempfile.mkstemp(prefix="rubato_ports_", suffix=".bfshell")
        with os.fdopen(fd, "w") as f:
            for command in commands:
                f.write(str(command).strip() + "\n")
            # The last configured context is `pm`.  Explicitly leave both the
            # port-manager shell and bfshell; otherwise `bfshell -f` waits on
            # stdin forever after consuming the command file.
            f.write("exit\nexit\n")
        return path

    def table(self, base_name):
        if self.bfrt_info is None:
            raise RuntimeError("BFRT is not connected")
        if base_name in self.table_cache:
            return self.table_cache[base_name]
        candidates = [
            base_name,
            "SwitchIngress.%s" % base_name,
            "SwitchEgress.%s" % base_name,
            "SwitchIngressDeparser.%s" % base_name,
            "pipe.%s" % base_name,
            "pipe.SwitchIngress.%s" % base_name,
            "pipe.SwitchEgress.%s" % base_name,
            "pipe.SwitchIngressDeparser.%s" % base_name,
        ]
        for name in candidates:
            try:
                table = self.bfrt_info.table_get(name)
                self.table_cache[base_name] = table
                return table
            except Exception:
                pass
        raise KeyError("BFRT table not found: %s" % base_name)

    def install_static_config(self):
        if self.args.dry_run:
            LOG.info("dry-run static config: %s", json.dumps(self.config, indent=2))
            return
        if self.aligned is not None:
            self.install_aligned_ports()
        self._install_fixed_forwarding()
        self._install_force_video_flows()
        self._clear_flow_policy_tables()
        self._clear_legacy_bloom()
        self._clear_rejected_flow_tables()
        self._install_media_prefixes()
        self._install_static_media_ips()
        self.set_active_bank(0)
        self.reset_cms_bank(1)
        self.reset_cms_bank(0)
        self.epoch_started = time.time()
        if self.aligned is None:
            self.install_lpf_config()
        if self.aligned is not None:
            self.aligned.prepare()
        elif self.args.install_tm:
            self.install_tm_config()
        if self.hardware_policy is not None:
            self.prepare_hardware_policy()

    def install_aligned_ports(self):
        if self.args.skip_port_init or not self.config.get("ports", {}).get("enabled", False):
            return
        table = self.bfrt_info.table_get("$PORT")
        ports = sorted(
            {
                int(p[k])
                for p in self.config["fixed_forwarding"]
                for k in ("ingress_port", "egress_port")
            }
        )
        for port in ports:
            keys = [self.gc.KeyTuple("$DEV_PORT", port)]
            key = table.make_key(keys)
            try:
                existing = next(table.entry_get(self.target, [key], {"from_hw": True}))[0].to_dict()
            except Exception as exc:
                if (
                    not isinstance(exc, StopIteration)
                    and "NOT_FOUND" not in str(exc)
                    and "not found" not in str(exc).lower()
                ):
                    raise
                existing = None
            if existing is not None and existing.get("$IS_VALID") is False:
                existing = None
            desired = [
                self.gc.DataTuple("$SPEED", str_val="BF_SPEED_100G"),
                self.gc.DataTuple("$FEC", str_val="BF_FEC_TYP_REED_SOLOMON"),
                self.gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_FORCE_DISABLE"),
                self.gc.DataTuple("$PORT_ENABLE", bool_val=True),
            ]
            if existing is None:
                table.entry_add(self.target, [key], [table.make_data(desired)])
            elif (
                existing.get("$SPEED") != "BF_SPEED_100G"
                or existing.get("$FEC") != "BF_FEC_TYP_REED_SOLOMON"
                or existing.get("$AUTO_NEGOTIATION") != "PM_AN_FORCE_DISABLE"
            ):
                raise RuntimeError(
                    "existing port differs from expected 100G/RS/AN-off: %s" % existing
                )
            elif not existing.get("$PORT_ENABLE"):
                table.entry_mod(
                    self.target,
                    [key],
                    [table.make_data([self.gc.DataTuple("$PORT_ENABLE", bool_val=True)])],
                )
            data = next(table.entry_get(self.target, [table.make_key(keys)], {"from_hw": True}))[
                0
            ].to_dict()
            if data.get("$SPEED") != "BF_SPEED_100G" or not data.get("$PORT_ENABLE"):
                raise RuntimeError("port configuration readback failed: %s" % data)
            LOG.info("verified 100G port %s enabled; link_up=%s", port, data.get("$PORT_UP"))

    def _install_fixed_forwarding(self):
        table = self.table("dmac")
        try:
            table.entry_del(self.target)
        except Exception:
            pass
        for item in self.config.get("fixed_forwarding", []):
            self.add_table_entry(
                "dmac",
                [self.gc.KeyTuple("ig_intr_md.ingress_port", int(item["ingress_port"]))],
                "SwitchIngress.set_port",
                [self.gc.DataTuple("port", int(item["egress_port"]))],
            )
        LOG.info(
            "installed %d fixed dmac forwarding entries",
            len(self.config.get("fixed_forwarding", [])),
        )

    def _install_force_video_flows(self):
        flows = self.config.get("force_video_flows", {})
        for table_name in ("force_video4", "force_video6"):
            try:
                self.table(table_name).entry_del(self.target)
            except Exception:
                pass
        for item in flows.get("ipv4", []):
            self.add_table_entry(
                "force_video4",
                [
                    self.gc.KeyTuple("hdr.ipv4.src_addr", ip_key_value(item["src_ip"])),
                    self.gc.KeyTuple("hdr.ipv4.dst_addr", ip_key_value(item["dst_ip"])),
                    self.gc.KeyTuple("md.protocol", int(item.get("protocol", 17))),
                    self.gc.KeyTuple("md.dst_port", int(item["dst_port"])),
                ],
                "SwitchIngress.force_video",
                [self.gc.DataTuple("platform_id", int(item.get("platform_id", 0)))],
            )
        for item in flows.get("ipv6", []):
            self.add_table_entry(
                "force_video6",
                [
                    self.gc.KeyTuple("hdr.ipv6.src_addr", ip_key_value(item["src_ip"])),
                    self.gc.KeyTuple("hdr.ipv6.dst_addr", ip_key_value(item["dst_ip"])),
                    self.gc.KeyTuple("md.protocol", int(item.get("protocol", 17))),
                    self.gc.KeyTuple("md.dst_port", int(item["dst_port"])),
                ],
                "SwitchIngress.force_video",
                [self.gc.DataTuple("platform_id", int(item.get("platform_id", 0)))],
            )
        count = len(flows.get("ipv4", [])) + len(flows.get("ipv6", []))
        if count:
            LOG.info("installed %d force-video test rules", count)

    def _install_media_prefixes(self):
        for table_name in ("ti_ip4_lpm", "ti_ip6_lpm"):
            try:
                self.table(table_name).entry_del(self.target)
            except Exception:
                pass
        for item in self.config.get("media_prefixes", {}).get("ipv4", []):
            self.add_media_prefix(item["prefix"], int(item.get("platform_id", 0)))
        for item in self.config.get("media_prefixes", {}).get("ipv6", []):
            self.add_media_prefix(item["prefix"], int(item.get("platform_id", 0)))

    def _install_static_media_ips(self):
        for table_name in ("td_ip4_exact", "td_ip6_exact"):
            try:
                self.table(table_name).entry_del(self.target)
            except Exception:
                pass
        for item in self.config.get("static_media_ips", {}).get("ipv4", []):
            self.confirm_video_ip(item["ip"], int(item.get("platform_id", 0)))
        for item in self.config.get("static_media_ips", {}).get("ipv6", []):
            self.confirm_video_ip(item["ip"], int(item.get("platform_id", 0)))
        for ip in self.video_identities.ips:
            self.install_video_identity(ip)

    def _clear_flow_policy_tables(self):
        for table_name in ("qoe_video4", "qoe_video6"):
            try:
                self.table(table_name).entry_del(self.target)
            except Exception:
                if self.aligned is not None:
                    raise
        self.policy_flow_keys = []
        self.flow_policy_cache.clear()
        LOG.info("cleared stale exact flow-policy entries")

    def flow_table_key(self, flow):
        if int(flow.ip_version) == 4:
            return "qoe_video4", [
                self.gc.KeyTuple("hdr.ipv4.src_addr", ip_key_value(flow.src_ip)),
                self.gc.KeyTuple("hdr.ipv4.dst_addr", ip_key_value(flow.dst_ip)),
                self.gc.KeyTuple("md.src_port", int(flow.src_port)),
                self.gc.KeyTuple("md.dst_port", int(flow.dst_port)),
                self.gc.KeyTuple("md.protocol", int(flow.protocol)),
            ]
        return "qoe_video6", [
            self.gc.KeyTuple("hdr.ipv6.src_addr", ip_key_value(flow.src_ip)),
            self.gc.KeyTuple("hdr.ipv6.dst_addr", ip_key_value(flow.dst_ip)),
            self.gc.KeyTuple("md.src_port", int(flow.src_port)),
            self.gc.KeyTuple("md.dst_port", int(flow.dst_port)),
            self.gc.KeyTuple("md.protocol", int(flow.protocol)),
        ]

    def install_flow_policy(self, flow, qid, policy_version=0, platform_id=0):
        if self.args.dry_run:
            LOG.info("dry-run flow policy %s -> q%s version=%s", flow, qid, policy_version)
            return
        table_name, keys = self.flow_table_key(flow)
        table = self.table(table_name)
        key = table.make_key(keys)
        policy_data = table.make_data(
            [
                self.gc.DataTuple("qid", int(qid)),
                self.gc.DataTuple("policy_version", int(policy_version)),
                self.gc.DataTuple("platform_id", int(platform_id)),
            ],
            "SwitchIngress.set_qoe_video",
        )
        known = flow in self.flow_policy_cache
        method = table.entry_mod if known else table.entry_add
        try:
            method(self.target, [key], [policy_data])
        except Exception as exc:
            message = str(exc).lower()
            if not any(
                s in message for s in ("already exists", "already_exists", "not found", "not_found")
            ):
                raise
            fallback = table.entry_add if known else table.entry_mod
            fallback(self.target, [key], [policy_data])
        self.flow_policy_cache.add(flow)
        response = table.entry_get(
            self.target,
            [table.make_key(keys)],
            {"from_hw": True},
        )
        try:
            data, _ = next(response)
        except StopIteration:
            raise RuntimeError("flow-policy readback missing for %s" % (flow,))
        values = data.to_dict()
        observed_qid = values.get("qid")
        if observed_qid is None or int(observed_qid) != int(qid):
            raise RuntimeError(
                "flow-policy qid readback mismatch for %s: expected %s observed %s"
                % (flow, qid, observed_qid)
            )
        # SDE can optimize the unused policy_version action argument away.
        # Versions are CP commit records, not a hardware atomic-version claim.
        if int(values.get("platform_id", -1)) != int(platform_id):
            raise RuntimeError("flow-policy platform readback mismatch: %s" % values)
        LOG.info("verified flow policy %s -> q%s", flow, qid)

    def delete_flow_policy(self, flow):
        if self.args.dry_run:
            return
        table_name, keys = self.flow_table_key(flow)
        try:
            self.delete_table_entry(table_name, keys)
        except Exception as exc:
            if "NOT_FOUND" not in str(exc) and "OBJECT_NOT_FOUND" not in str(exc):
                if self.aligned is not None:
                    raise
                LOG.debug("failed to delete flow policy %s: %s", flow, exc)
        self.flow_policy_cache.discard(flow)

    def add_table_entry(self, table_name, keys, action, data):
        table = self.table(table_name)
        table.entry_add(self.target, [table.make_key(keys)], [table.make_data(data, action)])

    def add_or_mod_table_entry(self, table_name, keys, action, data):
        table = self.table(table_name)
        key = table.make_key(keys)
        table_data = table.make_data(data, action)
        try:
            table.entry_add(self.target, [key], [table_data])
        except Exception as add_exc:
            if "ALREADY_EXISTS" not in str(add_exc):
                raise
            table.entry_mod(self.target, [key], [table_data])

    def delete_table_entry(self, table_name, keys):
        table = self.table(table_name)
        table.entry_del(self.target, [table.make_key(keys)])

    def mod_or_add_entry(self, table, keys, data):
        key = table.make_key(keys)
        table_data = table.make_data(data)
        try:
            table.entry_mod(self.target, [key], [table_data])
        except Exception:
            table.entry_add(self.target, [key], [table_data])

    def add_media_ip(self, ip_text, platform_id):
        ip_obj = ipaddress.ip_address(ip_text)
        if str(ip_obj) in self.video_identities.ips:
            self.install_video_identity(str(ip_obj))
            return
        table_name = "td_ip4_exact" if ip_obj.version == 4 else "td_ip6_exact"
        key_name = "hdr.ipv4.src_addr" if ip_obj.version == 4 else "hdr.ipv6.src_addr"
        self.add_or_mod_table_entry(
            table_name,
            [self.gc.KeyTuple(key_name, int(ip_obj))],
            "SwitchIngress.mark_td",
            [self.gc.DataTuple("platform_id", platform_id)],
        )
        LOG.info("installed DNS-shadow media IP %s platform=%s", ip_obj, platform_id)

    def video_identity_qid(self, ip_text=None):
        online = self.config.get("online_dbsp", {})
        # An explicit experimental no-control arm observes identity without QoS.
        if online.get("mode") == "no_control":
            return 0
        if self.aligned is not None:
            if ip_text is None:
                raise ValueError("DQA identity assignment requires the source identity")
            return self.aligned.identity_qid(str(ipaddress.ip_address(ip_text)))
        return int(self.config.get("video_q", 1))

    def install_video_identity(self, ip_text):
        if self.args.dry_run:
            return
        ip = ipaddress.ip_address(ip_text)
        name = "td_ip4_exact" if ip.version == 4 else "td_ip6_exact"
        field = "hdr.ipv4.src_addr" if ip.version == 4 else "hdr.ipv6.src_addr"
        platform = self.video_identities.ips[str(ip)]
        self.add_or_mod_table_entry(
            name,
            [self.gc.KeyTuple(field, int(ip))],
            "SwitchIngress.mark_video_ip",
            [
                self.gc.DataTuple("platform_id", platform),
                self.gc.DataTuple("qid", self.video_identity_qid(str(ip))),
            ],
        )
        table = self.table(name)
        data = next(
            table.entry_get(
                self.target, [table.make_key([self.gc.KeyTuple(field, int(ip))])], {"from_hw": True}
            )
        )[0].to_dict()
        if (
            int(data.get("qid", -1)) != self.video_identity_qid(str(ip))
            or int(data.get("platform_id", -1)) != platform
        ):
            raise RuntimeError("video IP identity readback mismatch: " + str(ip))

    def confirm_video_ip(self, ip_text, platform_id):
        ip = str(ipaddress.ip_address(ip_text))
        platform = self.video_identities.confirm(ip, int(platform_id))
        self.install_video_identity(ip)
        for flow in list(self.rejected_flows):
            if flow.src_ip == ip:
                self.delete_rejected_flow(flow)
                del self.rejected_flows[flow]
        for flow, state in self.candidates.items():
            if flow.src_ip == ip:
                state.platform_id = platform
                self.confirmed_flows.add(flow)
                if self.aligned is not None:
                    self.aligned.admit(flow)

    def add_media_prefix(self, prefix, platform_id):
        net = ipaddress.ip_network(prefix, strict=False)
        table_name = "ti_ip4_lpm" if net.version == 4 else "ti_ip6_lpm"
        key_name = "hdr.ipv4.src_addr" if net.version == 4 else "hdr.ipv6.src_addr"
        self.add_or_mod_table_entry(
            table_name,
            [self.gc.KeyTuple(key_name, int(net.network_address), prefix_len=net.prefixlen)],
            "SwitchIngress.mark_ti",
            [self.gc.DataTuple("platform_id", platform_id)],
        )
        LOG.info("installed media prefix %s platform=%s", net, platform_id)

    def _clear_rejected_flow_tables(self):
        for table_name in ("rejected_flow4", "rejected_flow6"):
            try:
                self.table(table_name).entry_del(self.target)
            except Exception:
                pass
        self.rejected_flows.clear()

    def _clear_legacy_bloom(self):
        depth = int(self.config.get("bloom_depth", 1024))
        for table_name in ("ba0", "ba1"):
            table = self.table(table_name)
            field = self.register_field(table_name)
            for index in range(depth):
                self.register_write_table(table, field, index, 0)
        LOG.info("cleared legacy BA Bloom registers; exact policy tables control qid selection")

    def rejected_flow_key(self, flow):
        if int(flow.ip_version) == 4:
            return (
                "rejected_flow4",
                [
                    self.gc.KeyTuple("hdr.ipv4.src_addr", ip_key_value(flow.src_ip)),
                    self.gc.KeyTuple("hdr.ipv4.dst_addr", ip_key_value(flow.dst_ip)),
                    self.gc.KeyTuple("md.src_port", int(flow.src_port)),
                    self.gc.KeyTuple("md.dst_port", int(flow.dst_port)),
                    self.gc.KeyTuple("md.protocol", int(flow.protocol)),
                ],
            )
        return (
            "rejected_flow6",
            [
                self.gc.KeyTuple("hdr.ipv6.src_addr", ip_key_value(flow.src_ip)),
                self.gc.KeyTuple("hdr.ipv6.dst_addr", ip_key_value(flow.dst_ip)),
                self.gc.KeyTuple("md.src_port", int(flow.src_port)),
                self.gc.KeyTuple("md.dst_port", int(flow.dst_port)),
                self.gc.KeyTuple("md.protocol", int(flow.protocol)),
            ],
        )

    def install_rejected_flow(self, flow):
        if self.args.dry_run:
            LOG.info("dry-run install rejected flow %s", flow)
            return True
        table_name, keys = self.rejected_flow_key(flow)
        try:
            self.add_or_mod_table_entry(table_name, keys, "SwitchIngress.mark_bb", [])
            return True
        except Exception as exc:
            LOG.warning("failed to install rejected flow table entry %s: %s", flow, exc)
            return False

    def delete_rejected_flow(self, flow):
        if self.args.dry_run:
            LOG.info("dry-run delete rejected flow %s", flow)
            return True
        table_name, keys = self.rejected_flow_key(flow)
        try:
            self.delete_table_entry(table_name, keys)
            return True
        except Exception as exc:
            if "NOT_FOUND" not in str(exc) and "OBJECT_NOT_FOUND" not in str(exc):
                LOG.debug("failed to delete rejected flow table entry %s: %s", flow, exc)
            return False

    def reject_ttl_s(self):
        return float(self.config.get("reject_ttl_s", 60.0))

    def reject_expired(self, reject_time, now):
        ttl = self.reject_ttl_s()
        return ttl > 0 and now - float(reject_time) >= ttl

    def expire_rejected_flows(self, now=None):
        now = time.time() if now is None else now
        if self.reject_ttl_s() <= 0:
            return
        expired = []
        for flow, reject_time in list(self.rejected_flows.items()):
            if self.reject_expired(reject_time, now):
                expired.append(flow)
        for flow in expired:
            self.delete_rejected_flow(flow)
            del self.rejected_flows[flow]
        if expired:
            LOG.info(
                "expired %d rejected-flow entries after %.1fs TTL",
                len(expired),
                self.reject_ttl_s(),
            )

    def set_active_bank(self, bank):
        if self.args.dry_run:
            self.active_bank = int(bank)
            LOG.info("dry-run active CMS bank -> %s", self.active_bank)
            return
        if self.aligned is not None and not self.cms_bank_ready[int(bank)]:
            self.reset_cms_bank(int(bank))
        table = self.table("cms_bank_select")
        table.default_entry_set(
            self.target,
            table.make_data([self.gc.DataTuple("bank", int(bank))], "SwitchIngress.set_cms_bank"),
        )
        self.active_bank = int(bank)
        self.cms_bank_ready[int(bank)] = False

    def install_lpf_config(self):
        count = int(self.config.get("lpf_index_count", 512))
        for table_name, prefix in (
            ("video_qdepth_short_lpf", "short"),
            ("video_qdepth_long_lpf", "long"),
        ):
            table = self.table(table_name)
            gain = float(self.config.get("%s_lpf_gain_time_constant_ns" % prefix, 50000000.0))
            decay = float(self.config.get("%s_lpf_decay_time_constant_ns" % prefix, gain))
            scale = int(self.config.get("%s_lpf_out_scale_down_factor" % prefix, 0))
            for idx in range(count):
                key = table.make_key([self.gc.KeyTuple("$LPF_INDEX", idx)])
                data = table.make_data(
                    [
                        self.gc.DataTuple("$LPF_SPEC_TYPE", str_val="SAMPLE"),
                        self.gc.DataTuple("$LPF_SPEC_GAIN_TIME_CONSTANT_NS", float_val=gain),
                        self.gc.DataTuple("$LPF_SPEC_DECAY_TIME_CONSTANT_NS", float_val=decay),
                        self.gc.DataTuple("$LPF_SPEC_OUT_SCALE_DOWN_FACTOR", scale),
                    ]
                )
                try:
                    table.entry_mod(self.target, [key], [data])
                except Exception:
                    table.entry_add(self.target, [key], [data])
            LOG.info("installed %s LPF config for %d video-state indices", prefix, count)

    def tm_table(self, suffix):
        tm = self.config.get("tm", {})
        archs = tm.get("arch_candidates", ["tf1", "tf2"])
        for arch in archs:
            try:
                return self.table("%s.tm.%s" % (arch, suffix))
            except Exception:
                pass
        raise KeyError("TM BFRT table not found: %s" % suffix)

    def install_tm_config(self):
        tm = self.config.get("tm", {})
        queues = tm.get("queues", [])
        if not queues:
            LOG.warning("--install-tm set but tm.queues is empty; TM queue config skipped")
            return
        if self.tm_backend() == "thrift":
            self.install_tm_config_thrift(queues)
            return
        sched_cfg = self.tm_table("queue.sched_cfg")
        sched_shaping = self.tm_table("queue.sched_shaping")
        default_priority = str(tm.get("default_priority", "HIGH"))
        video_priority = str(tm.get("video_priority", "LOW"))
        for item in queues:
            pg_id = int(item["pg_id"])
            default_queue = int(item.get("default_pg_queue", self.config.get("default_q", 0)))
            video_queue = int(item.get("video_pg_queue", self.config.get("video_q", 1)))
            default_weight = int(item.get("default_dwrr_weight", tm.get("default_dwrr_weight", 1)))
            video_weight = int(item.get("video_dwrr_weight", tm.get("video_dwrr_weight", 1)))
            self.configure_tm_queue(
                sched_cfg,
                sched_shaping,
                pg_id,
                default_queue,
                default_priority,
                None,
                default_weight,
            )
            self.configure_tm_queue(
                sched_cfg,
                sched_shaping,
                pg_id,
                video_queue,
                video_priority,
                item.get("initial_video_max_rate_kbps", tm.get("initial_video_max_rate_kbps")),
                video_weight,
            )

    def install_tm_config_thrift(self, queues):
        self.connect_tm()
        tm = self.config.get("tm", {})
        for item in queues:
            dev_port = int(item["dev_port"])
            video_queue = int(
                item.get("video_q", item.get("video_pg_queue", self.config.get("video_q", 1)))
            )
            default_queue = int(
                item.get("default_q", item.get("default_pg_queue", self.config.get("default_q", 0)))
            )
            self.configure_tm_queue_thrift(
                dev_port,
                default_queue,
                None,
                item,
                int(item.get("default_dwrr_weight", tm.get("default_dwrr_weight", 1))),
            )
            initial_rate = item.get(
                "initial_video_max_rate_kbps", tm.get("initial_video_max_rate_kbps")
            )
            self.configure_tm_queue_thrift(
                dev_port,
                video_queue,
                initial_rate,
                item,
                int(item.get("video_dwrr_weight", tm.get("video_dwrr_weight", 1))),
            )

    def configure_tm_queue(
        self, sched_cfg, sched_shaping, pg_id, pg_queue, priority, max_rate_kbps, dwrr_weight
    ):
        if not 0 <= int(dwrr_weight) <= 1023:
            raise ValueError("Tofino queue DWRR weight must be in [0, 1023]")
        max_enable = max_rate_kbps is not None
        keys = [self.gc.KeyTuple("pg_id", pg_id), self.gc.KeyTuple("pg_queue", pg_queue)]
        self.mod_or_add_entry(
            sched_cfg,
            keys,
            [
                self.gc.DataTuple("scheduling_enable", bool_val=True),
                self.gc.DataTuple("min_rate_enable", bool_val=False),
                self.gc.DataTuple("min_priority", str_val=str(priority)),
                self.gc.DataTuple("max_rate_enable", bool_val=bool(max_enable)),
                self.gc.DataTuple("max_priority", str_val=str(priority)),
                self.gc.DataTuple("dwrr_weight", int(dwrr_weight)),
            ],
        )
        if max_enable:
            tm = self.config.get("tm", {})
            self.mod_or_add_entry(
                sched_shaping,
                keys,
                [
                    self.gc.DataTuple("unit", str_val=str(tm.get("unit", "BPS"))),
                    self.gc.DataTuple(
                        "provisioning", str_val=str(tm.get("provisioning", "MIN_ERROR"))
                    ),
                    self.gc.DataTuple("max_rate", int(max_rate_kbps)),
                    self.gc.DataTuple("max_burst_size", int(tm.get("max_burst_size", 0))),
                ],
            )
        LOG.info(
            "configured TM pg=%s queue=%s priority=%s max_rate=%s dwrr_weight=%s",
            pg_id,
            pg_queue,
            priority,
            max_rate_kbps,
            dwrr_weight,
        )

    def configure_tm_queue_thrift(self, dev_port, qid, max_rate_kbps, item=None, dwrr_weight=1):
        if not 0 <= int(dwrr_weight) <= 1023:
            raise ValueError("Tofino queue DWRR weight must be in [0, 1023]")
        if self.args.dry_run:
            LOG.info(
                "dry-run TM thrift port=%s q=%s max_rate=%s dwrr_weight=%s",
                dev_port,
                qid,
                max_rate_kbps,
                dwrr_weight,
            )
            return
        self.connect_tm()
        tm = self.config.get("tm", {})
        item = item or {}
        dev = self.device_id()
        self.tm_client.tm_set_q_dwrr_weight(dev, int(dev_port), int(qid), int(dwrr_weight))
        burst = int(item.get("max_burst_size", tm.get("max_burst_size", 12000)))
        if max_rate_kbps is None or int(max_rate_kbps) <= 0:
            self.tm_client.tm_disable_q_max_shaping_rate(dev, int(dev_port), int(qid))
            self.tm_client.tm_complete_operations(dev)
            LOG.info("disabled TM max shaping devport=%s q=%s", dev_port, qid)
            return
        rate = int(max_rate_kbps)
        if self.aligned is not None:
            from tm_api_rpc.ttypes import tm_sched_shaper_provisioning_type_t

            self.tm_client.tm_set_q_shaping_rate_provisioning(
                dev,
                int(dev_port),
                int(qid),
                False,
                burst,
                rate,
                tm_sched_shaper_provisioning_type_t.RATE_UPPER,
            )
        else:
            self.tm_client.tm_set_q_shaping_rate(dev, int(dev_port), int(qid), False, burst, rate)
        self.tm_client.tm_enable_q_max_shaping_rate(dev, int(dev_port), int(qid))
        self.tm_client.tm_complete_operations(dev)
        LOG.info(
            "configured TM thrift devport=%s q=%s max_rate=%d kbps burst=%d",
            dev_port,
            qid,
            rate,
            burst,
        )

    def set_queue_scheduler(self, dev_port, qid, enabled):
        if self.args.dry_run:
            LOG.info("dry-run TM scheduler devport=%s q=%s enabled=%s", dev_port, qid, enabled)
            return
        self.connect_tm()
        method = self.tm_client.tm_enable_q_sched if enabled else self.tm_client.tm_disable_q_sched
        method(self.device_id(), int(dev_port), int(qid))
        self.tm_client.tm_complete_operations(self.device_id())

    def prepare_hardware_policy(self):
        policy = self.hardware_policy
        if policy is None:
            return
        if not self.args.install_tm:
            raise RuntimeError("--policy requires --install-tm so queues can be prepared safely")
        for lease in policy.leases:
            self.configure_tm_queue_thrift(
                lease.dev_port,
                lease.qid,
                lease.rate_kbps,
                {"max_burst_size": lease.burst_bytes},
            )
            self.set_queue_scheduler(lease.dev_port, lease.qid, False)
        LOG.info(
            "prepared policy group=%s version=%s queues=%d",
            policy.group_id,
            policy.version,
            len(policy.leases),
        )

    def activate_hardware_policy(self):
        policy = self.hardware_policy
        if policy is None or self.policy_active:
            return
        for item in policy.flows:
            flow = FlowKey(
                item["ip_version"],
                item["src_ip"],
                item["dst_ip"],
                item["src_port"],
                item["dst_port"],
                item["protocol"],
            )
            if policy.require_behavior_confirmation and flow not in self.confirmed_flows:
                continue
            self.install_flow_policy(flow, item["qid"], policy.version, item["platform_id"])
            self.policy_flow_keys.append(flow)
        self.policy_active = True
        LOG.info(
            "activated policy group=%s version=%s flows=%d",
            policy.group_id,
            policy.version,
            len(policy.flows),
        )

    def install_confirmed_policy_flow(self, flow):
        policy = self.hardware_policy
        if policy is None or not self.policy_active or flow in self.policy_flow_keys:
            return False
        for item in policy.flows:
            key = (
                item["ip_version"],
                item["src_ip"],
                item["dst_ip"],
                item["src_port"],
                item["dst_port"],
                item["protocol"],
            )
            if tuple(flow) == key:
                self.install_flow_policy(flow, item["qid"], policy.version, item["platform_id"])
                self.policy_flow_keys.append(flow)
                return True
        return False

    def panic_hardware_policy(self):
        policy = self.hardware_policy
        if policy is None or not self.policy_active:
            return
        for lease in policy.leases:
            self.set_queue_scheduler(lease.dev_port, lease.qid, True)
            self.configure_tm_queue_thrift(lease.dev_port, lease.qid, None)
            lease.state = DRAINING
        for flow in self.policy_flow_keys:
            self.delete_flow_policy(flow)
        self.policy_flow_keys = []
        self.policy_active = False
        LOG.warning("expired/panicked policy group=%s version=%s", policy.group_id, policy.version)

    def update_hardware_policy(self, now=None):
        policy = self.hardware_policy
        if policy is None:
            return
        now = time.time() if now is None else now
        if policy.is_expired(now):
            self.panic_hardware_policy()
        elif policy.is_due(now):
            self.activate_hardware_policy()
            self.update_policy_phase_gates(now)

    def update_policy_phase_gates(self, now):
        policy = self.hardware_policy
        if policy is None or not self.policy_active:
            return
        for lease in policy.leases:
            enabled = lease.scheduler_enabled(now, policy.activation_epoch_s)
            desired = ACTIVE if enabled else PREPARING
            if lease.state != desired:
                self.set_queue_scheduler(lease.dev_port, lease.qid, enabled)
                lease.state = desired

    def handle_dns_payload(self, payload):
        for hostname, ip_text, ttl in self.dns_parser.parse_response(payload, include_ttl=True):
            matched, platform_id = self.rules.match(hostname)
            if matched:
                if self.args.dry_run:
                    LOG.info(
                        "dry-run DNS match %s -> %s platform=%s", hostname, ip_text, platform_id
                    )
                else:
                    self.enqueue_dns_shadow_record(
                        hostname, ip_text, platform_id, "passive_dns", ttl
                    )

    def handle_candidate_digest(self, data):
        if self.aligned is not None:
            forwarding = {
                int(p["ingress_port"]): int(p["egress_port"])
                for p in self.config.get("fixed_forwarding", [])
            }
            if forwarding.get(int(data.get("ingress_port", -1))) != int(
                self.aligned.cfg["dev_port"]
            ):
                return
        flow = self.flow_from_digest(data)
        now = time.time()
        if flow in self.confirmed_flows:
            return
        known_ip = flow.src_ip in self.video_identities.ips
        reject_time = None if known_ip else self.rejected_flows.get(flow)
        if reject_time is not None:
            if self.reject_expired(reject_time, now):
                self.delete_rejected_flow(flow)
                del self.rejected_flows[flow]
            else:
                return
        state = self.candidates.get(flow)
        if state is None:
            if self.aligned is not None and len(self.candidates) >= int(
                self.aligned.cfg.get("max_observed_flows", 512)
            ):
                return  # Capacity exhaustion must not imply video confirmation.
            state = CandidateState(
                flow,
                self.register_index("cms_a0", data["hash0"]),
                self.register_index("cms_a1", data["hash1"]),
                int(data.get("platform_id", 0)),
                now,
            )
            if known_ip:
                state.platform_id = self.video_identities.ips[flow.src_ip]
            if self.aligned is not None:
                # q0 is an observation marker, not admission to a controlled queue.
                # It suppresses per-packet repeated digests while CMS keeps counting.
                if not known_ip:
                    self.install_flow_policy(flow, 0, 0, state.platform_id)
            self.candidates[flow] = state
            if known_ip:
                self.confirmed_flows.add(flow)
                if self.aligned is not None:
                    self.aligned.admit(flow)
            LOG.debug("new candidate %s h=(%d,%d)", flow, state.hash0, state.hash1)
        else:
            state.last_seen = now

    def flow_from_digest(self, data):
        version = int(data["ip_version"])
        if version == 4:
            src_ip = str(ipaddress.IPv4Address(int(data["src_ip"]) & 0xFFFFFFFF))
            dst_ip = str(ipaddress.IPv4Address(int(data["dst_ip"]) & 0xFFFFFFFF))
        else:
            src_ip = str(ipaddress.IPv6Address(int(data["src_ip"])))
            dst_ip = str(ipaddress.IPv6Address(int(data["dst_ip"])))
        return FlowKey(
            version,
            src_ip,
            dst_ip,
            int(data["src_port"]),
            int(data["dst_port"]),
            int(data["protocol"]),
        )

    def epoch_tick(self):
        old_bank = self.active_bank
        end = time.time()
        switched = False
        try:
            self.set_active_bank(1 - old_bank)
            switched = True
            end = time.time()
            self.epoch_ended = end
            self.cms_snapshot = self.read_cms_bank(old_bank) if not self.args.dry_run else None
            self.process_inactive_bank(old_bank)
            if self.aligned is not None:
                self.aligned.last_epoch = end
                self.aligned.tick(end)
            self.expire_rejected_flows()
            self.expire_shadow_ips()
        except Exception:
            if self.aligned is not None:
                for state in self.candidates.values():
                    state.windows = []
                    self.aligned.observe(state, None, self.epoch_started, end)
                self.aligned.release("invalid_cms_window")
            raise
        finally:
            self.cms_snapshot = None
            if switched:
                self.epoch_started = end
                if not self.args.dry_run:
                    try:
                        self.reset_cms_bank(old_bank)
                    except Exception:
                        if self.aligned is not None:
                            self.aligned.release("cms_reset_failed")
                        raise

    def process_inactive_bank(self, bank):
        now = self.epoch_ended if self.epoch_ended is not None else time.time()
        behavior_cfg = self.config.get("behavior", {})
        horizon_s = float(behavior_cfg.get("sample_duration_seconds", 60.0))
        window_s = float(behavior_cfg.get("window_seconds", 0.5))
        elapsed = now - self.epoch_started
        valid_window = elapsed > 0
        for flow, state in list(self.candidates.items()):
            if flow.src_ip in self.video_identities.ips:
                self.confirmed_flows.add(flow)
            observed_bytes = self.cms_estimate(bank, state.hash0, state.hash1)
            if self.aligned is not None:
                if not valid_window:
                    state.windows = []
                    self.aligned.observe(state, None, self.epoch_started, now)
                    continue
                self.aligned.observe(state, observed_bytes, self.epoch_started, now)
            state.windows.append(
                int(round(observed_bytes * window_s / elapsed)) if valid_window else 0
            )
            if self.aligned is not None:
                state.windows = state.windows[-max(1, int(horizon_s / window_s)) :]
            if flow in self.confirmed_flows:
                continue
            decision = classify_windows(state.windows, behavior_cfg)
            state.last_decision = decision
            if decision["behavior_match"]:
                self.confirm_video_ip(flow.src_ip, state.platform_id)
                if self.hardware_policy is None and self.aligned is None:
                    self.install_flow_policy(
                        flow, self.config.get("video_q", 1), 0, state.platform_id
                    )
                self.confirmed_flows.add(flow)
                self.install_confirmed_policy_flow(flow)
                if self.aligned is None:
                    del self.candidates[flow]
                LOG.info(
                    "confirmed media flow %s reason=%s bursts=%d bytes=%d",
                    flow,
                    decision["reason"],
                    decision["burst_count"],
                    decision["total_burst_bytes"],
                )
            elif now - state.first_seen >= horizon_s:
                if self.aligned is not None:
                    self.delete_flow_policy(flow)
                if self.install_rejected_flow(flow):
                    self.rejected_flows[flow] = now
                else:
                    LOG.warning("rejected flow but failed to install rejected-flow entry: %s", flow)
                del self.candidates[flow]
                LOG.info("rejected candidate flow %s reason=%s", flow, decision["reason"])

    def cms_estimate(self, bank, hash0, hash1):
        if self.args.dry_run:
            return 0
        prefix = "cms_a" if bank == 0 else "cms_b"
        if self.cms_snapshot is not None:
            left = self.cms_snapshot[prefix + "0"][self.register_index(prefix + "0", hash0)]
            right = self.cms_snapshot[prefix + "1"][self.register_index(prefix + "1", hash1)]
            if len(left) != len(right):
                raise RuntimeError("inconsistent CMS pipe counts")
            return sum(min(a, b) for a, b in zip(left, right))
        return min(
            self.register_read("%s0" % prefix, hash0), self.register_read("%s1" % prefix, hash1)
        )

    def read_cms_bank(self, bank):
        prefix = "cms_a" if bank == 0 else "cms_b"
        snapshot = {}
        for name in (prefix + "0", prefix + "1"):
            indices = sorted(
                {
                    self.register_index(name, h)
                    for s in self.candidates.values()
                    for h in (s.hash0, s.hash1)
                }
            )
            table, entries = self.table(name), {}
            for start in range(0, len(indices), 128):
                keys = [
                    table.make_key([self.gc.KeyTuple("$REGISTER_INDEX", i)])
                    for i in indices[start : start + 128]
                ]
                for data, key in table.entry_get(self.target, keys, {"from_hw": True}):
                    idx = int(key.to_dict()["$REGISTER_INDEX"]["value"])
                    values = data.to_dict()[self.register_field(name)]
                    entries[idx] = (
                        [int(v) for v in values] if isinstance(values, list) else [int(values)]
                    )
                    if any(v >= 0xFFFFFFFF for v in entries[idx]):
                        raise RuntimeError("saturated CMS counter")
            if set(entries) != set(indices):
                raise RuntimeError("incomplete CMS snapshot")
            snapshot[name] = entries
        return snapshot

    def bloom_index(self, index):
        return int(index) % int(self.config.get("bloom_depth", 1024))

    def register_index(self, table_name, index):
        if table_name.startswith(("cms_a", "cms_b")):
            return int(index) % int(self.config.get("cms_depth", 1024))
        if table_name.startswith(("ba", "bb")):
            return self.bloom_index(index)
        return int(index)

    def reset_cms_bank(self, bank):
        self.cms_bank_ready[int(bank)] = False
        prefix = "cms_a" if bank == 0 else "cms_b"
        depth = int(self.config.get("cms_depth", 1024))
        for table_name in ("%s0" % prefix, "%s1" % prefix):
            table = self.table(table_name)
            field = self.register_field(table_name)
            for start in range(0, depth, 128):
                keys = [
                    table.make_key([self.gc.KeyTuple("$REGISTER_INDEX", idx)])
                    for idx in range(start, min(start + 128, depth))
                ]
                values = [table.make_data([self.gc.DataTuple(field, 0)]) for _ in keys]
                table.entry_mod(self.target, keys, values)
        self.cms_bank_ready[int(bank)] = True

    def write_bloom(self, bloom, hash0, hash1):
        if self.args.dry_run:
            LOG.info("dry-run write %s bits %d/%d", bloom, hash0, hash1)
            return True
        ok0 = self.register_write("%s0" % bloom, hash0, 1)
        ok1 = self.register_write("%s1" % bloom, hash1, 1)
        return bool(ok0 and ok1)

    def register_read(self, table_name, index):
        index = self.register_index(table_name, index)
        try:
            table = self.table(table_name)
            resp = table.entry_get(
                self.target,
                [table.make_key([self.gc.KeyTuple("$REGISTER_INDEX", int(index))])],
                {"from_hw": True},
            )
            data = next(resp)[0].to_dict()
        except Exception as exc:
            # Some SDE/BFRT register tables report untouched cells as absent
            # instead of returning an explicit zero value.
            if "Entry not found" in str(exc):
                return 0
            self.warn_register_read_failure(table_name, index, exc)
            return 0
        for value in data.values():
            if value is None:
                continue
            if isinstance(value, list):
                if not value or value[0] is None:
                    continue
                return int(value[0])
            return int(value)
        return 0

    def register_write(self, table_name, index, value):
        index = self.register_index(table_name, index)
        try:
            table = self.table(table_name)
            field = self.register_field(table_name)
        except Exception as exc:
            self.warn_register_write_failure(table_name, index, value, exc, exc)
            return False
        return self.register_write_table(table, field, index, value)

    def register_write_table(self, table, field, index, value):
        key = table.make_key([self.gc.KeyTuple("$REGISTER_INDEX", int(index))])
        data = table.make_data([self.gc.DataTuple(field, int(value))])
        try:
            table.entry_mod(self.target, [key], [data])
            return True
        except Exception as mod_exc:
            try:
                table.entry_add(self.target, [key], [data])
                return True
            except Exception as add_exc:
                self.warn_register_write_failure(field, index, value, mod_exc, add_exc)
                return False

    def warn_register_write_failure(self, field, index, value, mod_exc, add_exc):
        count = self.register_write_failures.get(field, 0)
        if count < 8:
            LOG.warning(
                "BFRT register write skipped field=%s index=%s value=%s mod_error=%s add_error=%s",
                field,
                index,
                value,
                mod_exc,
                add_exc,
            )
        elif count == 8:
            LOG.warning("suppressing further BFRT register write warnings for %s", field)
        self.register_write_failures[field] = count + 1

    def warn_register_read_failure(self, table_name, index, exc):
        count = self.register_read_failures.get(table_name, 0)
        if count < 8:
            LOG.warning(
                "BFRT register read returned 0 table=%s index=%s error=%s", table_name, index, exc
            )
        elif count == 8:
            LOG.warning("suppressing further BFRT register read warnings for %s", table_name)
        self.register_read_failures[table_name] = count + 1

    def register_field(self, table_name):
        if table_name.startswith("video_qdepth_") or table_name in (
            "video_egress_bytes",
            "queue_egress_packets",
            "queue_residence_max",
        ):
            return "SwitchEgress.%s.f1" % table_name
        return "SwitchIngress.%s.f1" % table_name

    def drain_digests(self, timeout=0.05):
        if self.args.dry_run or self.interface is None or self.bfrt_info is None:
            return
        if self.digest_receiver is not None:
            self.digest_receiver.drain(
                self.handle_candidate_digest, self.handle_dns_digest_metadata
            )
            return
        try:
            digest = self.interface.digest_get(timeout=timeout)
        except Exception:
            return
        for learn_name, handler in (
            ("pipe.SwitchIngressDeparser.candidate_digest", self.handle_candidate_digest),
            ("candidate_digest", self.handle_candidate_digest),
            ("pipe.SwitchIngressDeparser.dns_digest", self.handle_dns_digest_metadata),
            ("dns_digest", self.handle_dns_digest_metadata),
        ):
            try:
                learn = self.bfrt_info.learn_get(learn_name)
                for item in learn.make_data_list(digest):
                    handler(item.to_dict())
                return
            except Exception:
                pass

    def handle_dns_digest_metadata(self, data):
        LOG.debug("DNS digest metadata received: %s", data)

    def queue_state(self, item, video_queue):
        dev_port = int(item.get("dev_port", item.get("egress_devport", 0)))
        key = (dev_port, int(video_queue))
        tm = self.config.get("tm", {})
        initial = item.get("initial_video_max_rate_kbps", tm.get("initial_video_max_rate_kbps", 0))
        if key not in self.queue_states:
            self.queue_states[key] = QueueControlState(initial)
        return self.queue_states[key]

    def tm_q_count_cells(self, dev_port, qid, item):
        if self.tm_backend() != "thrift":
            return None
        self.connect_tm()
        pipe = int(item.get("pipe", self.config.get("tm", {}).get("pipe", 0)))
        usage = self.tm_client.tm_get_q_usage(self.device_id(), pipe, int(dev_port), int(qid))
        return int(usage.count)

    def tm_q_shaping_rate_kbps(self, dev_port, qid):
        if self.tm_backend() != "thrift":
            return None
        try:
            self.connect_tm()
            rate = self.tm_client.tm_get_q_shaping_rate(self.device_id(), int(dev_port), int(qid))
            return int(rate.rate)
        except Exception as exc:
            LOG.debug("could not read TM shaping rate devport=%s q=%s: %s", dev_port, qid, exc)
            return None

    def queue_scheduler_read(self, dev_port, qid):
        self.connect_tm()
        physical = self.tm_client.tm_get_port_pipe_phys_q(self.device_id(), int(dev_port), int(qid))
        table = self.tm_table("queue.sched_cfg")
        # Convert the physical queue index back to this target's port-group slot.
        slots = int(self.config.get("tm", {}).get("queues_per_port_group", 32))
        key = table.make_key(
            [
                self.gc.KeyTuple("pg_id", physical.phys_queue // slots),
                self.gc.KeyTuple("pg_queue", physical.phys_queue % slots),
            ]
        )
        target = self.gc.Target(device_id=self.device_id(), pipe_id=physical.pipe)
        return next(
            table.entry_get(target, [key], {"from_hw": True}, p4_name=self.args.program_name)
        )[0].to_dict()

    def estimate_video_input_rate(self, item, state, dev_port, video_queue, now):
        tm = self.config.get("tm", {})
        fallback_rate = float(
            item.get("video_input_rate_kbps", tm.get("video_input_rate_kbps", 0)) or 0
        )
        lpf_index = int(item.get("lpf_index", dev_port))
        try:
            egress_bytes = self.register_read("video_egress_bytes", lpf_index)
        except Exception as exc:
            if not self.warned_no_video_counter:
                LOG.warning(
                    "video_egress_bytes unavailable; falling back to configured/current rate: %s",
                    exc,
                )
                self.warned_no_video_counter = True
            return fallback_rate or float(state.current_rate_kbps)

        q_count_cells = self.tm_q_count_cells(dev_port, video_queue, item)
        if q_count_cells is None:
            q_count_cells = self.register_read("video_qdepth_last_sample", lpf_index)
        state.current_q_count_cells = int(q_count_cells)

        if state.last_time is None:
            state.last_time = now
            state.last_egress_bytes = egress_bytes
            state.last_q_count_cells = q_count_cells
            return fallback_rate

        elapsed = max(now - state.last_time, 0.001)
        byte_delta = int(egress_bytes) - int(state.last_egress_bytes)
        if byte_delta < 0:
            byte_delta += 2**32
        cell_bytes = int(tm.get("cell_size_bytes", 80))
        queue_delta_bytes = (int(q_count_cells) - int(state.last_q_count_cells)) * cell_bytes
        egress_rate_kbps = float(byte_delta) * 8.0 / elapsed / 1000.0
        if egress_rate_kbps <= 0 and state.shaping_enabled and state.current_rate_kbps > 0:
            if q_count_cells > 0 or queue_delta_bytes > 0:
                egress_rate_kbps = float(state.current_rate_kbps)
        queue_growth_kbps = max(0.0, float(queue_delta_bytes)) * 8.0 / elapsed / 1000.0
        state.last_time = now
        state.last_egress_bytes = egress_bytes
        state.last_q_count_cells = q_count_cells
        state.input_rate_kbps = egress_rate_kbps + queue_growth_kbps
        return state.input_rate_kbps or fallback_rate

    def choose_video_rate(self, item, state, short_ratio, long_ratio, input_rate_kbps):
        tm = self.config.get("tm", {})
        idle_epsilon = float(tm.get("idle_ratio_epsilon", 0.001))
        if input_rate_kbps <= 0 and short_ratio <= idle_epsilon and long_ratio <= idle_epsilon:
            return state.current_rate_kbps or int(
                item.get("initial_video_max_rate_kbps", tm.get("initial_video_max_rate_kbps", 0))
                or 0
            )
        low = float(tm.get("long_lpf_low_ratio", 0.10))
        high = float(tm.get("long_lpf_high_ratio", 0.40))
        target = float(tm.get("long_lpf_target_ratio", (low + high) / 2.0))
        target = max(target, 0.01)
        min_rate = int(item.get("min_video_rate_kbps", tm.get("min_video_rate_kbps", 1000)))
        max_rate = int(item.get("max_video_rate_kbps", tm.get("max_video_rate_kbps", 100000000)))
        initial_rate = int(
            item.get("initial_video_max_rate_kbps", tm.get("initial_video_max_rate_kbps", 0)) or 0
        )
        reference_rate = max(
            float(input_rate_kbps or 0),
            float(state.current_rate_kbps or 0),
            float(initial_rate),
            float(min_rate),
        )

        gain = float(tm.get("long_lpf_gain", 1.0))
        factor = 1.0 + gain * ((float(long_ratio) - target) / target)
        factor = max(float(tm.get("min_control_factor", 0.25)), factor)
        factor = min(float(tm.get("max_control_factor", 4.0)), factor)
        rate = reference_rate * factor

        if long_ratio < low:
            rate = min(rate, reference_rate * float(tm.get("below_low_multiplier", 0.75)))
        elif long_ratio > high:
            rate = max(rate, reference_rate * float(tm.get("above_high_multiplier", 1.25)))

        t60 = float(tm.get("threshold_60", 0.60))
        t75 = float(tm.get("threshold_75", 0.75))
        t90 = float(tm.get("threshold_90", 0.90))
        if short_ratio >= t90:
            return None
        if short_ratio >= t75:
            rate = max(rate, reference_rate * float(tm.get("multiplier_75", 4)))
        elif short_ratio >= t60:
            rate = max(rate, reference_rate * float(tm.get("multiplier_60", 2)))

        rate = max(float(min_rate), rate)
        if max_rate > 0:
            rate = min(float(max_rate), rate)
        return int(rate)

    def apply_video_queue_rate(
        self, item, video_queue, rate_kbps, sched_cfg=None, sched_shaping=None
    ):
        dev_port = int(item.get("dev_port", item.get("egress_devport", 0)))
        state = self.queue_state(item, video_queue)
        deadband = float(self.config.get("tm", {}).get("rate_update_deadband", 0.05))
        if rate_kbps is None:
            if state.shaping_enabled:
                if self.tm_backend() == "thrift":
                    self.configure_tm_queue_thrift(
                        dev_port,
                        video_queue,
                        None,
                        item,
                        int(
                            item.get(
                                "video_dwrr_weight",
                                self.config.get("tm", {}).get("video_dwrr_weight", 1),
                            )
                        ),
                    )
                else:
                    pg_id = int(item["pg_id"])
                    self.configure_tm_queue(
                        sched_cfg,
                        sched_shaping,
                        pg_id,
                        video_queue,
                        self.config.get("tm", {}).get("video_priority", "LOW"),
                        None,
                        int(
                            item.get(
                                "video_dwrr_weight",
                                self.config.get("tm", {}).get("video_dwrr_weight", 1),
                            )
                        ),
                    )
                state.shaping_enabled = False
                state.current_rate_kbps = 0
            return

        rate = int(rate_kbps)
        if state.shaping_enabled and state.current_rate_kbps > 0:
            change = abs(rate - state.current_rate_kbps) / float(state.current_rate_kbps)
            if change < deadband:
                actual = self.tm_q_shaping_rate_kbps(dev_port, video_queue)
                if actual is None or abs(actual - rate) / float(max(rate, 1)) < deadband:
                    return
                LOG.info(
                    "reapplying TM rate devport=%s q=%s desired=%s actual=%s",
                    dev_port,
                    video_queue,
                    rate,
                    actual,
                )
        if self.tm_backend() == "thrift":
            self.configure_tm_queue_thrift(
                dev_port,
                video_queue,
                rate,
                item,
                int(
                    item.get(
                        "video_dwrr_weight", self.config.get("tm", {}).get("video_dwrr_weight", 1)
                    )
                ),
            )
        else:
            pg_id = int(item["pg_id"])
            self.configure_tm_queue(
                sched_cfg,
                sched_shaping,
                pg_id,
                video_queue,
                self.config.get("tm", {}).get("video_priority", "LOW"),
                rate,
                int(
                    item.get(
                        "video_dwrr_weight", self.config.get("tm", {}).get("video_dwrr_weight", 1)
                    )
                ),
            )
        state.shaping_enabled = True
        state.current_rate_kbps = rate

    def update_queue_control(self):
        if self.aligned is not None:
            return self.aligned.tick()
        if not self.args.install_tm or self.args.dry_run or self.hardware_policy is not None:
            return
        tm = self.config.get("tm", {})
        queue_depth_max = self.config.get("queue_depth_max")
        queues = tm.get("queues", [])
        if queue_depth_max is None or not queues:
            LOG.debug("TM queue control skipped: queue_depth_max or tm.queues missing")
            return
        sched_cfg = None
        sched_shaping = None
        if self.tm_backend() != "thrift":
            sched_cfg = self.tm_table("queue.sched_cfg")
            sched_shaping = self.tm_table("queue.sched_shaping")
        max_depth = float(queue_depth_max)
        for item in queues:
            lpf_index = int(item.get("lpf_index", item.get("dev_port", 0)))
            short_lpf = self.register_read("video_qdepth_short_value", lpf_index)
            long_lpf = self.register_read("video_qdepth_long_value", lpf_index)
            dev_port = int(item.get("dev_port", item.get("egress_devport", 0)))
            video_queue = int(
                item.get("video_q", item.get("video_pg_queue", self.config.get("video_q", 1)))
            )
            state = self.queue_state(item, video_queue)
            now = time.time()
            input_rate = self.estimate_video_input_rate(item, state, dev_port, video_queue, now)
            lpf_short_ratio = float(short_lpf) / max_depth if max_depth > 0 else 0.0
            lpf_long_ratio = float(long_lpf) / max_depth if max_depth > 0 else 0.0
            q_ratio = float(state.current_q_count_cells) / max_depth if max_depth > 0 else 0.0
            short_ratio = max(lpf_short_ratio, q_ratio)
            long_ratio = max(lpf_long_ratio, q_ratio)
            if input_rate <= 0 and state.current_q_count_cells == 0:
                rate = state.current_rate_kbps or int(
                    item.get(
                        "initial_video_max_rate_kbps", tm.get("initial_video_max_rate_kbps", 0)
                    )
                    or 0
                )
            else:
                rate = self.choose_video_rate(item, state, short_ratio, long_ratio, input_rate)
            self.apply_video_queue_rate(item, video_queue, rate, sched_cfg, sched_shaping)
            LOG.info(
                "queue-control devport=%s q=%s short=%.3f long=%.3f q=%.3f input=%.1fkbps rate=%s",
                dev_port,
                video_queue,
                short_ratio,
                long_ratio,
                q_ratio,
                input_rate,
                "unlimited" if rate is None else rate,
            )

    def start_measurement(self):
        self.start_dns_shadow_server()
        if not self.args.dry_run:
            wire = self.config.get("wire_observation", {})
            wire_enabled = wire.get("enabled", False)
            self.digest_receiver = DigestReceiver(
                self.interface, self.bfrt_info, wire["raw_file"] if wire_enabled else None
            )
            self.digest_receiver.start()
            if wire_enabled:
                self.wire_observer = WireObservation(self, self.digest_receiver, wire)
                self.wire_observer.start()
        if self.aligned is not None and not self.args.dry_run:
            self.aligned.heartbeat(time.time())
            self.watchdog = subprocess.Popen(
                [
                    sys.executable,
                    os.path.join(os.path.dirname(__file__), "watchdog.py"),
                    "--config",
                    os.path.abspath(self.args.config),
                    "--parent-pid",
                    str(os.getpid()),
                    "--heartbeat",
                    os.path.join(self.aligned.root, self.aligned.cfg["heartbeat_file"]),
                ]
            )

    def run(self):
        self.maybe_install_ports()
        self.connect()
        signal.signal(signal.SIGTERM, lambda *_: self.stop_requested.set())
        signal.signal(signal.SIGINT, lambda *_: self.stop_requested.set())
        try:
            self.install_static_config()
            self.start_measurement()
            next_epoch = time.time() + float(self.config.get("sample_interval_s", 0.5))
            next_queue = time.time() + float(self.config.get("queue_control_interval_s", 1.0))
            self.run_loop(next_epoch, next_queue, time.monotonic())
        finally:
            try:
                if (
                    self.wire_observer is not None
                    and self.wire_observer.record["status"] == "capturing"
                ):
                    closed = self.wire_observer.finish()
                    if closed["status"] == "capture_failed":
                        raise RuntimeError("ASIC capture failed: %s" % closed.get("close_failures"))
                elif self.digest_receiver is not None and self.digest_receiver.thread.is_alive():
                    self.digest_receiver.stop()
            finally:
                released = False
                try:
                    if self.aligned is not None:
                        self.aligned.release("controller_shutdown")
                        self.aligned.restore_port_buffer()
                    released = True
                finally:
                    if released and self.watchdog is not None and self.watchdog.poll() is None:
                        self.watchdog.terminate()
                        self.watchdog.wait(timeout=5)
                    if self.dns_shadow_httpd is not None:
                        self.dns_shadow_httpd.shutdown()

    def run_loop(self, next_epoch, next_queue, started):
        while not self.stop_requested.is_set():
            if (
                self.args.duration_seconds
                and time.monotonic() - started >= self.args.duration_seconds
            ):
                return
            if self.digest_receiver is not None:
                if any(
                    self.digest_receiver.stats[key]
                    for key in (
                        "unknown_digest",
                        "parse_errors",
                        "receive_errors",
                        "queue_overflows",
                        "write_errors",
                        "handler_errors",
                    )
                ):
                    raise RuntimeError("Digest observation failed: %s" % self.digest_receiver.stats)
            if self.watchdog is not None and self.watchdog.poll() is not None:
                self.aligned.release("watchdog_died")
                raise RuntimeError("independent watchdog exited")
            self.safe_step("hardware-policy", self.update_hardware_policy)
            self.safe_step("dns-shadow-records", self.process_dns_shadow_records)
            self.safe_step("digests", self.drain_digests)
            now = time.time()
            if now >= next_epoch:
                interval = float(self.config.get("sample_interval_s", 0.5))
                self.safe_step("epoch", self.epoch_tick)
                next_epoch = (
                    now + interval if now - next_epoch > interval else next_epoch + interval
                )
            if now >= next_queue and self.aligned is None:
                interval = float(self.config.get("queue_control_interval_s", 1.0))
                self.safe_step("queue-control", self.update_queue_control)
                next_queue = (
                    now + interval if now - next_queue > interval else next_queue + interval
                )
            time.sleep(0.005)

    def safe_step(self, name, func, *args):
        try:
            return func(*args)
        except Exception as exc:
            count = self.loop_failures.get(name, 0)
            if count < 8:
                LOG.warning("%s failed; controller keeps running: %s", name, exc, exc_info=True)
            elif count == 8:
                LOG.warning("suppressing further %s failure tracebacks", name)
            self.loop_failures[name] = count + 1
            return None


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Rubato Tofino BFRT controller")
    parser.add_argument("--config", default="rubato_config.yaml")
    parser.add_argument("--program-name", default=None)
    parser.add_argument("--install-ports", action="store_true")
    parser.add_argument("--skip-port-init", action="store_true")
    parser.add_argument("--install-tm", action="store_true")
    parser.add_argument(
        "--dns-shadow-listen",
        default=None,
        help="listen address for NIC2 DNS-shadow updates, e.g. 0.0.0.0:18080",
    )
    parser.add_argument("--disable-dns-shadow-server", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--policy", default=None, help="compiled rubato_hardware_policy_v1 JSON")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument(
        "--run-id", default=None, help="Exact experiment identity for owned process lifecycle"
    )
    parser.add_argument(
        "--duration-seconds",
        type=float,
        default=None,
        help="Bounded trial runtime; default runs until stopped",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    config = load_config(args.config)
    if args.program_name is None:
        args.program_name = str(config.get("program_name", "rubato"))
    RubatoController(config, args).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
