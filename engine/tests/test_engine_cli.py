import json
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import engine_cli  # noqa: E402


def test_module_dotted_path():
    assert (
        engine_cli.module_dotted_path("exploits/routers/tplink/foo")
        == "embedxpl.modules.exploits.routers.tplink.foo"
    )
    assert (
        engine_cli.module_dotted_path("embedxpl.modules.exploits.foo")
        == "embedxpl.modules.exploits.foo"
    )
    assert (
        engine_cli.module_dotted_path("modules/exploits/foo")
        == "embedxpl.modules.exploits.foo"
    )


def test_parse_options():
    parsed = engine_cli.parse_options(
        ["target=192.168.1.1", "port=80", "verbose=true", "name=lab-router"]
    )
    assert parsed == {
        "target": "192.168.1.1",
        "port": 80,
        "verbose": True,
        "name": "lab-router",
    }


def test_parse_options_rejects_malformed():
    with pytest.raises(ValueError):
        engine_cli.parse_options(["target"])


def test_target_allowed(tmp_path, monkeypatch):
    allow = tmp_path / "allowed.json"
    allow.write_text(json.dumps({"networks": ["192.168.1.0/24"]}))
    monkeypatch.setattr(engine_cli, "ALLOWED_FILE", str(allow))

    assert engine_cli.target_allowed("192.168.1.10") is True
    assert engine_cli.target_allowed("10.0.0.5") is False


def test_target_allowed_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(engine_cli, "ALLOWED_FILE", str(tmp_path / "missing.json"))
    assert engine_cli.target_allowed("192.168.1.10") is False


def test_rank_module_prefers_matching_port_and_vendor():
    host = type("Host", (), {
        "vendor_guess": "cisco",
        "model_guess": "",
        "open_ports": [80, 443],
        "banners": {80: "Cisco IOS web UI"},
    })()
    ranked = engine_cli.rank_module(
        "embedxpl.modules.exploits.cisco.web_ui",
        {"name": "Cisco Web UI", "devices": ["Cisco Router"]},
        80,
        host,
    )
    assert ranked["score"] > 0
    assert ranked["likely_fail"] is False
    assert "vendor match" in ranked["reason"]


def test_rank_module_flags_legacy_protocol_and_closed_port():
    host = type("Host", (), {
        "vendor_guess": "cisco",
        "model_guess": "",
        "open_ports": [80, 443],
        "banners": {},
    })()
    ranked = engine_cli.rank_module(
        "embedxpl.modules.creds.cisco.telnet_default_creds",
        {"name": "Cisco Telnet Default Creds", "devices": []},
        23,
        host,
    )
    assert ranked["score"] < 0
    assert ranked["likely_fail"] is True
    assert "legacy protocol" in ranked["reason"]


def test_build_magic_packet():
    packet = engine_cli.build_magic_packet("8c:61:a3:7a:d5:63")
    assert len(packet) == 102
    assert packet[:6] == b"\xff" * 6
    assert packet[6:12] == bytes.fromhex("8c61a37ad563")
    assert packet[6:12] * 16 == packet[6:]


def test_normalize_mac_rejects_invalid():
    assert engine_cli.normalize_mac("WLAN0") is None
    assert engine_cli.normalize_mac("8c-61-a3-7a-d5-63") == "8C:61:A3:7A:D5:63"


def test_jsonable_dataclass():
    @dataclass
    class Example:
        ip: str
        ports: list

    value = engine_cli.jsonable(Example("192.168.1.1", [80, 443]))
    assert value == {"ip": "192.168.1.1", "ports": [80, 443]}
