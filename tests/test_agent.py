"""Tests for scripts/agent.py — SID generation, rule validation, anomaly classification."""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_proj_root = Path(__file__).resolve().parent.parent
if str(_proj_root) not in sys.path:
    sys.path.insert(0, str(_proj_root))

from scripts.agent import _sid, _validate_rule

# The @tool wrapped function — call it directly via its .func
from scripts.agent import analyze_anomaly


# ---------------------------------------------------------------------------
# _sid
# ---------------------------------------------------------------------------

def test_sid_in_range():
    sid = _sid("e8358fb5-101a-43ba-93cd-8f9b95e30ac6")
    assert 1_000_000 <= sid <= 9_999_999


def test_sid_deterministic():
    sid1 = _sid("e8358fb5-101a-43ba-93cd-8f9b95e30ac6")
    sid2 = _sid("e8358fb5-101a-43ba-93cd-8f9b95e30ac6")
    assert sid1 == sid2


def test_sid_different_inputs():
    sid1 = _sid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    sid2 = _sid("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    assert sid1 != sid2


# ---------------------------------------------------------------------------
# _validate_rule
# ---------------------------------------------------------------------------

def test_validate_rule_valid():
    rule = """alert modbus $EXTERNAL_NET any -> $HOME_NET 502 (
    msg:"test";
    sid:1234567;
    classtype:attempted-admin;
    rev:1;)"""
    assert _validate_rule(rule) == "PASSED"


def test_validate_rule_missing_sid():
    rule = """alert modbus $EXTERNAL_NET any -> $HOME_NET 502 (
    msg:"test";
    classtype:attempted-admin;)"""
    assert "FAILED" in _validate_rule(rule)
    assert "sid" in _validate_rule(rule)


def test_validate_rule_missing_classtype():
    rule = """alert modbus $EXTERNAL_NET any -> $HOME_NET 502 (
    msg:"test";
    sid:1234567;)"""
    assert "FAILED" in _validate_rule(rule)
    assert "classtype" in _validate_rule(rule)


def test_validate_rule_missing_modbus():
    rule = """alert tcp $EXTERNAL_NET any -> $HOME_NET 502 (
    msg:"test";
    sid:1234567;
    classtype:attempted-admin;)"""
    assert "FAILED" in _validate_rule(rule)
    assert "modbus" in _validate_rule(rule)


# ---------------------------------------------------------------------------
# analyze_anomaly logic (deterministic classification)
# ---------------------------------------------------------------------------

ANALYZE = analyze_anomaly.func


def test_analyze_write_with_cavitation():
    result = ANALYZE(
        anomaly_score=-0.05,
        tank_level_mean=5.0,
        tank_level_max=6.0,
        has_write_fc=True,
        function_codes=[3, 6],
        source_ips=["172.24.0.10"],
        plc_ip="172.21.0.10",
    )
    assert "UNAUTHORIZED_WRITE_WITH_CAVITATION" in result
    assert "cavitation" in result
    assert "T0815" in result


def test_analyze_write_only():
    result = ANALYZE(
        anomaly_score=-0.0011,
        tank_level_mean=70.0,
        tank_level_max=80.0,
        has_write_fc=True,
        function_codes=[3, 6],
        source_ips=["172.24.0.10", "172.22.0.10"],
        plc_ip="172.21.0.10",
    )
    assert "UNAUTHORIZED_MODBUS_WRITE" in result
    assert "172.23.0.4" in result
    assert "T0836" in result


def test_analyze_overfill_with_scanning():
    result = ANALYZE(
        anomaly_score=-0.0355,
        tank_level_mean=60.0,
        tank_level_max=92.2,
        has_write_fc=False,
        function_codes=[3, 131],
        source_ips=["172.24.0.10"],
        plc_ip="172.21.0.10",
    )
    assert "OVERFILL_WITH_SCANNING" in result
    assert "T0846" in result


def test_analyze_scanning_only():
    result = ANALYZE(
        anomaly_score=-0.06,
        tank_level_mean=35.0,
        tank_level_max=40.0,
        has_write_fc=False,
        function_codes=[3, 131],
        source_ips=["172.24.0.10"],
        plc_ip="172.21.0.10",
    )
    assert "NETWORK_SCANNING" in result
    assert "T0846" in result


def test_analyze_overfill_only():
    result = ANALYZE(
        anomaly_score=-0.01,
        tank_level_mean=50.0,
        tank_level_max=93.6,
        has_write_fc=False,
        function_codes=[3],
        source_ips=["172.22.0.10"],
        plc_ip="172.21.0.10",
    )
    assert "TANK_OVERFILL" in result
    assert "T0815" in result


def test_analyze_cavitation_only():
    result = ANALYZE(
        anomaly_score=-0.06,
        tank_level_mean=5.0,
        tank_level_max=6.0,
        has_write_fc=False,
        function_codes=[3],
        source_ips=["172.22.0.10"],
        plc_ip="172.21.0.10",
    )
    assert "CAVITATION_RISK" in result
    assert "T0836" in result


def test_analyze_generic():
    result = ANALYZE(
        anomaly_score=-0.05,
        tank_level_mean=45.0,
        tank_level_max=55.0,
        has_write_fc=False,
        function_codes=[3],
        source_ips=["172.22.0.10"],
        plc_ip="172.21.0.10",
    )
    assert "GENERIC_ANOMALY" in result
    assert "Unclassified" in result
