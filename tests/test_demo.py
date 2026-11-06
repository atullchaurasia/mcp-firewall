"""The scripted attack demo is part of the test suite: every scenario must match its expectation."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from mcpfw.proxy import PYTHON_TOKEN, resolve_command

DEMO = Path(__file__).resolve().parent.parent / "demo" / "attack_demo.py"


def load_demo():
    spec = importlib.util.spec_from_file_location("attack_demo", DEMO)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up in sys.modules
    spec.loader.exec_module(module)
    return module


@pytest.mark.anyio
@pytest.mark.parametrize("anyio_backend", ["asyncio"])
async def test_attack_demo_matches_expectations(anyio_backend):
    demo = load_demo()
    rows = await demo.run_all()
    text, ok = demo.render(rows)
    assert ok, text

    by_id = {scenario.id: (without, with_fw) for scenario, without, with_fw in rows}
    assert by_id["S1"][1].firewall == ["ASK R3 -> approved"] and by_id["S1"][1].task
    assert by_id["S2"][1].firewall == ["BLOCK R1"]
    assert by_id["S3"][1].firewall == ["BLOCK R1"]
    assert by_id["S4"][1].firewall == ["ASK R2 -> declined"]
    assert "hid get_forecast (rug pull)" in by_id["S5"][1].firewall
    assert "hid weather_alerts (poisoned)" in by_id["S5"][1].firewall
    assert all(without.attack for sid, (without, _) in by_id.items() if sid != "S1")
    assert not any(with_fw.attack for _, with_fw in by_id.values())


def test_python_token_resolves_to_current_interpreter():
    assert resolve_command(PYTHON_TOKEN) == sys.executable
    assert resolve_command("node") == "node"
