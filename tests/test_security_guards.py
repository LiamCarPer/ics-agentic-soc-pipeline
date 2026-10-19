"""Tests for path confinement, rule guards and UUID/IP validation."""

import pytest

from src.security.guards import canonical_uuid, validate_ip, validate_rule
from src.security.paths import OUTPUTS_DIR, safe_output_path


def test_safe_output_path_accepts_flat_filename(tmp_path):
    path = safe_output_path("incident_abc.md", base=tmp_path)
    assert path == (tmp_path / "incident_abc.md").resolve()


@pytest.mark.parametrize(
    "filename",
    [
        "../incident.md",
        "incident_a/../../pwn.md",
        "/etc/cron.d/pwn",
        "..",
        ".",
        "",
        "bad\x00name.md",
    ],
)
def test_safe_output_path_rejects_escapes(filename):
    with pytest.raises(ValueError):
        safe_output_path(filename)


def test_safe_output_path_defaults_to_outputs():
    path = safe_output_path("incident_test.md")
    assert path.parent == OUTPUTS_DIR.resolve()


def test_canonical_uuid_accepts_uuid():
    value = canonical_uuid("E8358FB5-101A-43BA-93CD-8F9B95E30AC6")
    assert value == "e8358fb5-101a-43ba-93cd-8f9b95e30ac6"


@pytest.mark.parametrize(
    "value", ["a/../../pwn-a-b-c-d", "not-a-uuid", "", "../../etc/passwd"]
)
def test_canonical_uuid_rejects_malformed(value):
    with pytest.raises(ValueError):
        canonical_uuid(value)


@pytest.mark.parametrize("value", ["172.24.0.10", "::1", "2001:db8::1"])
def test_validate_ip_accepts_valid(value):
    assert validate_ip(value)


@pytest.mark.parametrize("value", ["172.24.0.999", "1.2.3.4\nIGNORE", ""])
def test_validate_ip_rejects_invalid(value):
    with pytest.raises(ValueError):
        validate_ip(value)


def valid_rule() -> str:
    return (
        "alert modbus 172.24.0.10 any -> 172.21.0.10 502 (\n"
        '    msg:"OT SOC - Unauthorized Modbus Write";\n'
        '    content:"|00 06|";\n'
        "    flow:established,to_server;\n"
        "    sid:6306854;\n"
        "    classtype:attempted-admin;\n"
        "    rev:1;)"
    )


def test_valid_rule_passes():
    assert validate_rule(valid_rule()) == "PASSED"


@pytest.mark.parametrize(
    "rule,expected",
    [
        (
            'drop modbus any any -> any 502 (msg:"pwn"; sid:1234567; classtype:attempted-admin; rev:1;)',
            "alert modbus",
        ),
        (
            'alert modbus any any -> any 502 (msg:"pwn"; sid:123; classtype:attempted-admin; rev:1;)',
            "sid must be",
        ),
        (
            'alert tcp any any -> any 502 (msg:"pwn"; sid:1234567; classtype:attempted-admin; rev:1;)',
            "alert modbus",
        ),
        (
            'alert modbus any any -> any 502 (msg:"pwn"; sid:1234567; rev:1;',
            "unbalanced",
        ),
        (
            'alert modbus any any -> any 502 (msg:""; sid:1234567; classtype:attempted-admin; rev:1;)',
            "msg",
        ),
    ],
)
def test_rule_guard_rejects_bad_rules(rule, expected):
    result = validate_rule(rule)
    assert result.startswith("FAILED")
    assert expected in result
