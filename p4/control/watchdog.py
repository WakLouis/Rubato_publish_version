"""Independent control-host watchdog; cannot protect against loss of the host itself."""

import argparse
import json
import logging
import os
import time

from rubato_controller import RubatoController, load_config, parse_args


def withdraw_shaping(controller, online):
    """Rate-controller failure must not change classification or queue routing."""
    controller.connect_tm()
    for q in range(1, int(online["video_queues"]) + 1):
        controller.tm_client.tm_disable_q_max_shaping_rate(
            controller.device_id(), int(online["dev_port"]), q
        )
    controller.tm_client.tm_complete_operations(controller.device_id())
    controller.connect()
    for q in range(1, int(online["video_queues"]) + 1):
        if controller.queue_scheduler_read(int(online["dev_port"]), q)["max_rate_enable"]:
            raise RuntimeError("watchdog shaping disable readback failed")


def write_recovery(path, parent_pid, generation, state):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".tmp", "w") as handle:
        json.dump(
            {
                "parent_pid": parent_pid,
                "generation": generation,
                "state": state,
                "timestamp": time.time(),
            },
            handle,
        )
    os.replace(path + ".tmp", path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--parent-pid", required=True, type=int)
    parser.add_argument("--heartbeat", required=True)
    args = parser.parse_args()
    config = load_config(args.config)
    online = config["online_dbsp"]
    config["online_dbsp"] = dict(online, enabled=False)
    config["client_id"] = int(config.get("client_id", 0)) + 100
    config["bfrt_bind"] = False
    control_args = parse_args(
        ["--program-name", config["program_name"], "--disable-dns-shadow-server"]
    )
    controller = RubatoController(config, control_args)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    recovery_path = os.path.join(
        root, online.get("watchdog_recovery_file", online["heartbeat_file"] + ".recovery")
    )
    started, released = time.monotonic(), False
    release_generation = None
    while True:
        alive = True
        try:
            os.kill(args.parent_pid, 0)
        except ProcessLookupError:
            alive = False
        try:
            with open(args.heartbeat) as handle:
                heartbeat = json.load(handle)
            last = heartbeat["monotonic"] if heartbeat.get("pid") == args.parent_pid else started
        except (OSError, ValueError, KeyError):
            last = started
        expired = time.monotonic() - last > float(online["plan_ttl_s"])
        if (not alive or expired or release_generation is not None) and not released:
            try:
                if release_generation is None:
                    release_generation = "{}:{}".format(os.getpid(), time.monotonic())
                write_recovery(recovery_path, args.parent_pid, release_generation, "releasing")
                withdraw_shaping(controller, online)
                write_recovery(recovery_path, args.parent_pid, release_generation, "released")
                logging.warning(
                    "watchdog disabled shaping; video identities and queue mappings preserved: alive=%s expired=%s",
                    alive,
                    expired,
                )
                released = True
            except Exception:
                logging.exception("watchdog release failed; retrying")
                controller.tm_client = None
        if alive and not expired and released:
            released = False
            release_generation = None
        if not alive and released:
            return
        time.sleep(0.5)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    main()
