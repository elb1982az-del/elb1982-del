#!/usr/bin/env python3
"""JSON CLI bridge between the RouterXPL-Forge Android app and EmbedXPL-Forge.

Designed to run inside the Kali NetHunter chroot. Every command prints exactly
one JSON object to stdout on success or failure, so the APK can parse it.

Safety defaults:
  * `check` is a read-only probe and is always allowed for in-scope modules.
  * `run` requires BOTH an explicit `--confirm I_AUTHORIZE` flag and a target
    inside `allowed_networks.json`.
  * Interactive prompts are disabled; a module that tries to prompt fails fast.
"""

from __future__ import annotations

import argparse
import builtins
import contextlib
import io
import ipaddress
import json
import os
import re
import socket
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, List, Optional

EMBEDXPL_ROOT = os.environ.get("EMBEDXPL_ROOT", "/opt/EmbedXPL-Forge")
ALLOWED_FILE = os.environ.get(
    "RXPL_ALLOWED_NETWORKS",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "allowed_networks.json"),
)
DEFAULT_TIMEOUT = 120.0

# The Android controller launches us with a pipe on stdin. Some dependency
# code can block on a stdin read in that situation, so detach it immediately.
try:
    devnull_fd = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull_fd, 0)
    os.close(devnull_fd)
except Exception:
    pass

if EMBEDXPL_ROOT not in sys.path:
    sys.path.insert(0, EMBEDXPL_ROOT)


def jsonable(value: Any) -> Any:
    """Recursively convert dataclasses/objects into JSON-safe values."""
    if is_dataclass(value) and not isinstance(value, type):
        return jsonable(asdict(value))
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [jsonable(v) for v in value]
    if hasattr(value, "__slots__"):
        return {k: jsonable(getattr(value, k, None)) for k in value.__slots__}
    if hasattr(value, "__dict__"):
        return jsonable(vars(value))
    return str(value)


def emit(payload: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(jsonable(payload), ensure_ascii=False))
    sys.stdout.write("\n")
    sys.stdout.flush()


def fail(command: str, message: str, **extra: Any) -> int:
    emit({"ok": False, "command": command, "error": message, **extra})
    return 1


def target_allowed(target: str) -> bool:
    """Return True only if target is inside a user-declared lab CIDR."""
    if not os.path.exists(ALLOWED_FILE):
        return False
    try:
        with open(ALLOWED_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        networks = data.get("networks", []) if isinstance(data, dict) else []
        ip = ipaddress.ip_address(target)
        for cidr in networks:
            if ip in ipaddress.ip_network(str(cidr), strict=False):
                return True
    except Exception:
        return False
    return False


def allowed_networks() -> List[str]:
    """Return the user-declared lab CIDRs."""
    if not os.path.exists(ALLOWED_FILE):
        return []
    try:
        with open(ALLOWED_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        networks = data.get("networks", []) if isinstance(data, dict) else []
        return [str(item) for item in networks]
    except Exception:
        return []


def normalize_mac(mac: str) -> Optional[str]:
    value = mac.strip().upper().replace("-", ":")
    if not re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", value):
        return None
    return value


def build_magic_packet(mac: str) -> bytes:
    value = normalize_mac(mac)
    if value is None:
        raise ValueError("Invalid MAC address: {}".format(mac))
    octets = bytes(int(part, 16) for part in value.split(":"))
    return b"\xff" * 6 + octets * 16


def cmd_wol(args: argparse.Namespace) -> int:
    """Send a Wake-on-LAN magic packet inside a user-declared lab network."""
    mac = normalize_mac(args.mac)
    if mac is None:
        return fail("wol", "Invalid MAC address: {}".format(args.mac))

    try:
        target_net = ipaddress.ip_network(args.network, strict=False)
    except ValueError as exc:
        return fail("wol", "Invalid network: {}".format(exc))

    allowed = False
    broadcasts: List[str] = []
    for cidr in allowed_networks():
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if target_net.version != net.version:
            continue
        if target_net.subnet_of(net):
            allowed = True
            addr = str(net.broadcast_address)
            if addr not in broadcasts:
                broadcasts.append(addr)
    if not allowed:
        return fail(
            "wol",
            "Refusing: network is not inside allowed_networks.json. "
            "Add your lab CIDR before sending Wake-on-LAN.",
        )

    packet = build_magic_packet(mac)
    sent_to: List[str] = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for broadcast in broadcasts + ["255.255.255.255"]:
            for _ in range(max(1, min(args.count, 5))):
                try:
                    sock.sendto(packet, (broadcast, 9))
                    if broadcast not in sent_to:
                        sent_to.append(broadcast)
                except OSError as exc:
                    return fail("wol", "Broadcast failed on {}: {}".format(broadcast, exc))

    emit({
        "ok": True,
        "command": "wol",
        "mac": mac,
        "network": str(target_net),
        "broadcasts": sent_to,
        "packet_bytes": len(packet),
        "authorized_network": True,
    })
    return 0


def module_dotted_path(human_path: str) -> str:
    """Convert `exploits/routers/foo` to a dotted import path."""
    cleaned = human_path.strip().strip("/").replace("/", ".")
    if cleaned.startswith("embedxpl."):
        return cleaned
    if cleaned.startswith("modules."):
        return "embedxpl." + cleaned
    return "embedxpl.modules." + cleaned


def safe_input_disabled(*_args: Any, **_kwargs: Any) -> str:
    raise RuntimeError("Interactive prompts are disabled in the mobile bridge")


def instantiate(module_path: str, options: Dict[str, Any]):
    from embedxpl.core.exploit.utils import import_exploit

    cls = import_exploit(module_dotted_path(module_path))
    instance = cls()
    for key, value in options.items():
        if not hasattr(instance, key):
            raise ValueError("Unknown module option: {}".format(key))
        setattr(instance, key, value)
    return instance


def module_metadata(instance) -> Dict[str, Any]:
    name = type(instance).__name__
    info = getattr(instance, "_{}__info__".format(name), None) or {}
    return {
        "name": info.get("name", name),
        "description": info.get("description", ""),
        "severity": info.get("severity", ""),
        "cvss": info.get("cvss", ""),
        "cve": info.get("cve", []),
        "devices": info.get("devices", []),
        "references": info.get("references", []),
        "options": list(getattr(instance, "options", [])),
    }


def run_with_output(fn, timeout: float) -> Dict[str, Any]:
    """Execute fn in a worker thread, capturing stdout and enforcing a timeout."""
    buffer = io.StringIO()
    started = time.time()
    original_input = builtins.input
    builtins.input = safe_input_disabled
    result: Dict[str, Any] = {}
    try:
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(fn)
                try:
                    value = future.result(timeout=timeout)
                    result = {"value": value, "error": None}
                except FutureTimeout:
                    future.cancel()
                    result = {"value": None, "error": "Module timed out after {}s".format(timeout)}
                except BaseException as exc:  # noqa: BLE001 - surface module failures
                    result = {"value": None, "error": "{}: {}".format(type(exc).__name__, exc)}
    finally:
        builtins.input = original_input
    result["output"] = buffer.getvalue()[-20000:]
    result["elapsed_s"] = round(time.time() - started, 2)
    return result


def cmd_doctor(_args: argparse.Namespace) -> int:
    try:
        import embedxpl
        from embedxpl.core.exploit.utils import index_modules

        modules = index_modules()
        emit({
            "ok": True,
            "command": "doctor",
            "embedxpl_root": EMBEDXPL_ROOT,
            "module_count": len(modules),
            "allowed_networks_file": ALLOWED_FILE,
            "allowed_networks_configured": os.path.exists(ALLOWED_FILE),
        })
        return 0
    except Exception as exc:  # noqa: BLE001
        return fail("doctor", "Engine import failed: {}".format(exc))


def cmd_discover(args: argparse.Namespace) -> int:
    try:
        from embedxpl.core.discovery import NetworkDiscovery

        scanner = NetworkDiscovery(args.network, timing=args.timing)
        hosts = scanner.scan()
        emit({
            "ok": True,
            "command": "discover",
            "network": args.network,
            "count": len(hosts),
            "hosts": [jsonable(host) for host in hosts],
        })
        return 0
    except Exception as exc:  # noqa: BLE001
        return fail("discover", str(exc), traceback=traceback.format_exc()[-4000:])


PORT_PROTOCOLS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    53: "dns",
    80: "http",
    139: "smb",
    161: "snmp",
    162: "snmp",
    443: "https",
    445: "smb",
    554: "rtsp",
    1900: "upnp",
    3389: "rdp",
    5060: "sip",
    5900: "vnc",
    8080: "http",
    8081: "http",
    8443: "https",
    8888: "http",
    10000: "http",
}

LEGACY_TOKENS = (
    "telnet",
    "ftp",
    "snmpv1",
    "snmp v1",
    "snmpv2",
    "snmp v2",
    "smbv1",
    "smb v1",
    "sslv3",
    "ssl v3",
    "tlsv1",
    "tls 1.0",
    "tls 1.1",
    "wep",
    "wps",
    "rc4",
    "md5",
    "sha1",
    "upnp",
)


def rank_module(dotted: str, meta: Dict[str, Any], port: Optional[int], host: Any) -> Dict[str, Any]:
    """Score a module against a fingerprint and flag likely-fail matches."""
    open_ports = list(getattr(host, "open_ports", []) or [])
    banners = getattr(host, "banners", {}) or {}
    vendor = str(getattr(host, "vendor_guess", "") or "").strip().lower()
    model = str(getattr(host, "model_guess", "") or "").strip().lower()
    devices = meta.get("devices", []) or []
    if isinstance(devices, str):
        devices = [devices]
    haystack = " ".join(
        [dotted, str(meta.get("name", "")), str(meta.get("description", ""))]
        + [str(item) for item in devices]
        + [str(value) for value in banners.values()]
    ).lower()

    score = 0
    reasons: List[str] = []
    if vendor and vendor in haystack:
        score += 5
        reasons.append("vendor match")
    elif model and model in haystack:
        score += 4
        reasons.append("model match")

    if port is not None:
        if port in open_ports:
            score += 4
            reasons.append("port {} open".format(port))
        else:
            score -= 5
            reasons.append("port {} not open".format(port))

    for probe_port, protocol in PORT_PROTOCOLS.items():
        if probe_port in open_ports and protocol in haystack:
            score += 2
            reasons.append("{} service".format(protocol))
            break

    legacy = []
    for token in LEGACY_TOKENS:
        if re.search(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])", haystack):
            legacy.append(token)
    if legacy:
        score -= 2
        reasons.append("legacy protocol")

    likely_fail = bool(legacy) or (port is not None and port not in open_ports)
    return {
        "score": score,
        "likely_fail": likely_fail,
        "reason": "; ".join(reasons),
    }


def cmd_fingerprint(args: argparse.Namespace) -> int:
    try:
        from embedxpl.core.discovery import NetworkDiscovery

        scanner = NetworkDiscovery(args.target, timing=4)
        hosts = scanner.scan()
        if not hosts:
            return fail("fingerprint", "No fingerprint data for {}".format(args.target))
        host = hosts[0]
        modules = []
        for dotted in host.matched_modules[:200]:
            human = dotted.replace("embedxpl.modules.", "").replace(".", "/")
            try:
                from embedxpl.core.exploit.utils import import_exploit

                full_path = module_dotted_path(human)
                cls = import_exploit(full_path)
                instance = cls()
                meta = module_metadata(instance)
                port = getattr(instance, "port", None)
                if not isinstance(port, int):
                    port = None
                ranked = rank_module(full_path, meta, port, host)
                modules.append({
                    "path": human,
                    "title": getattr(cls, "title", "") or human,
                    "metadata": meta,
                    "port": port,
                    **ranked,
                })
            except Exception as exc:  # noqa: BLE001 - skip modules that cannot load
                modules.append({
                    "path": human,
                    "title": human,
                    "metadata": {},
                    "port": None,
                    "score": -10,
                    "likely_fail": True,
                    "reason": "module could not be analyzed: {}".format(exc),
                })
        modules.sort(key=lambda item: (-int(item.get("score", 0)), item.get("path", "")))
        emit({
            "ok": True,
            "command": "fingerprint",
            "target": args.target,
            "host": jsonable(host),
            "modules": modules,
        })
        return 0
    except Exception as exc:  # noqa: BLE001
        return fail("fingerprint", str(exc), traceback=traceback.format_exc()[-4000:])


def parse_options(raw_options: List[str]) -> Dict[str, Any]:
    options: Dict[str, Any] = {}
    for item in raw_options:
        key, sep, value = item.partition("=")
        if not sep:
            raise ValueError("Option must be key=value: {}".format(item))
        if value.lower() in ("true", "false"):
            options[key] = value.lower() == "true"
        else:
            try:
                options[key] = int(value)
            except ValueError:
                options[key] = value
    return options


def cmd_check(args: argparse.Namespace) -> int:
    try:
        options = parse_options(args.option)
        options.setdefault("target", args.target)
        if args.port is not None:
            options.setdefault("port", args.port)
        instance = instantiate(args.module, options)
        meta = module_metadata(instance)

        execution = run_with_output(lambda: bool(instance.check()), args.timeout)
        emit({
            "ok": execution["error"] is None,
            "command": "check",
            "target": args.target,
            "module": args.module,
            "metadata": meta,
            "vulnerable": execution["value"],
            "error": execution["error"],
            "output": execution["output"],
            "elapsed_s": execution["elapsed_s"],
        })
        return 0 if execution["error"] is None else 1
    except Exception as exc:  # noqa: BLE001
        return fail("check", str(exc), traceback=traceback.format_exc()[-4000:])


def cmd_run(args: argparse.Namespace) -> int:
    if args.confirm != "I_AUTHORIZE":
        return fail("run", "Refusing: explicit --confirm I_AUTHORIZE is required")
    if not target_allowed(args.target):
        return fail(
            "run",
            "Refusing: target is not inside allowed_networks.json. "
            "Add your lab CIDR before running exploits.",
        )
    try:
        options = parse_options(args.option)
        options.setdefault("target", args.target)
        if args.port is not None:
            options.setdefault("port", args.port)
        instance = instantiate(args.module, options)
        meta = module_metadata(instance)
        execution = run_with_output(lambda: instance.run(), args.timeout)
        emit({
            "ok": execution["error"] is None,
            "command": "run",
            "target": args.target,
            "module": args.module,
            "metadata": meta,
            "result": jsonable(execution["value"]),
            "error": execution["error"],
            "output": execution["output"],
            "elapsed_s": execution["elapsed_s"],
            "authorized_target": True,
        })
        return 0 if execution["error"] is None else 1
    except Exception as exc:  # noqa: BLE001
        return fail("run", str(exc), traceback=traceback.format_exc()[-4000:])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RouterXPL-Forge mobile engine bridge")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="Verify the EmbedXPL engine is importable")

    discover = sub.add_parser("discover", help="Discover live devices on a CIDR")
    discover.add_argument("--network", required=True)
    discover.add_argument("--timing", type=int, default=4)

    fingerprint = sub.add_parser("fingerprint", help="Fingerprint one host and list modules")
    fingerprint.add_argument("--target", required=True)

    check = sub.add_parser("check", help="Run a safe vulnerability check")
    check.add_argument("--module", required=True)
    check.add_argument("--target", required=True)
    check.add_argument("--port", type=int)
    check.add_argument("--option", action="append", default=[])
    check.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)

    run = sub.add_parser("run", help="Run an exploit against an explicitly authorized target")
    run.add_argument("--module", required=True)
    run.add_argument("--target", required=True)
    run.add_argument("--port", type=int)
    run.add_argument("--option", action="append", default=[])
    run.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    run.add_argument("--confirm", default="")

    wol = sub.add_parser("wol", help="Wake a previously discovered device on the lab network")
    wol.add_argument("--mac", required=True, help="MAC address of the sleeping device")
    wol.add_argument("--network", required=True, help="Lab CIDR the device belongs to")
    wol.add_argument("--count", type=int, default=3)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    handlers = {
        "doctor": cmd_doctor,
        "discover": cmd_discover,
        "fingerprint": cmd_fingerprint,
        "check": cmd_check,
        "run": cmd_run,
        "wol": cmd_wol,
    }
    try:
        return handlers[args.command](args)
    except Exception as exc:  # noqa: BLE001
        return fail(args.command, str(exc), traceback=traceback.format_exc()[-4000:])


if __name__ == "__main__":
    raise SystemExit(main())
