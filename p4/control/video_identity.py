"""Monotonic video-IP identities; observation expiry never removes an identity."""

import ipaddress
import json
import os
import tempfile


class VideoIdentities(object):
    def __init__(self, path=None):
        self.path = path
        self.ips = {}
        if path and os.path.exists(path):
            with open(path) as handle:
                value = json.load(handle)
            if value.get("schema") != "rubato_video_identities_v1":
                raise ValueError("unsupported video identity registry")
            for ip, platform in value["ips"].items():
                self.ips[str(ipaddress.ip_address(ip))] = self.platform(platform)

    @staticmethod
    def platform(value):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
            raise ValueError("invalid video platform ID")
        return value

    def confirm(self, ip, platform):
        ip = str(ipaddress.ip_address(ip))
        platform = self.platform(platform)
        if ip in self.ips:
            return self.ips[ip]
        updated = dict(self.ips)
        updated[ip] = platform
        if self.path:
            directory = os.path.dirname(os.path.abspath(self.path))
            os.makedirs(directory, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=".video-identities-", dir=directory)
            try:
                with os.fdopen(fd, "w") as handle:
                    json.dump(
                        {"schema": "rubato_video_identities_v1", "ips": updated},
                        handle,
                        sort_keys=True,
                    )
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        self.ips = updated
        return platform
