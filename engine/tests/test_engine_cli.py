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


def test_jsonable_dataclass():
    @dataclass
    class Example:
        ip: str
        ports: list

    value = engine_cli.jsonable(Example("192.168.1.1", [80, 443]))
    assert value == {"ip": "192.168.1.1", "ports": [80, 443]}
