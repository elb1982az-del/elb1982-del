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

                cls = import_exploit(dotted)
                modules.append({
                    "path": human,
                    "title": getattr(cls, "title", "") or human,
                    "metadata": module_metadata(cls()),
                })
            except Exception:  # noqa: BLE001 - skip modules that cannot load
                modules.append({"path": human, "title": human, "metadata": {}})
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
    discover.add_argument("--timing", type=int, default=3)

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
    }
    try:
        return handlers[args.command](args)
    except Exception as exc:  # noqa: BLE001
        return fail(args.command, str(exc), traceback=traceback.format_exc()[-4000:])


if __name__ == "__main__":
    raise SystemExit(main())
