"""Tests for src/rag.py — classification, query building, and ChromaDB retrieval."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_proj_root = Path(__file__).resolve().parent.parent
if str(_proj_root) not in sys.path:
    sys.path.insert(0, str(_proj_root))

from src.rag import _classify_anomaly, _build_query, retrieve_context


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def write_alert():
    return {
        "plc_ip": "172.21.0.10",
        "window_summary": {
            "tank_level_mean": 70.78,
            "tank_level_max": 80.4,
            "has_write_fc": 1,
            "source_ips": ["172.24.0.10", "172.22.0.10"],
            "function_codes": [3, 6],
        },
    }


@pytest.fixture
def cavitation_alert():
    return {
        "plc_ip": "172.21.0.10",
        "window_summary": {
            "tank_level_mean": 5.0,
            "tank_level_max": 5.5,
            "has_write_fc": 0,
            "source_ips": ["172.22.0.10"],
            "function_codes": [3],
        },
    }


# ---------------------------------------------------------------------------
# _classify_anomaly
# ---------------------------------------------------------------------------


def test_classify_anomaly_write_with_cavitation():
    alert = {
        "window_summary": {
            "tank_level_mean": 5.0,
            "has_write_fc": 1,
        }
    }
    result = _classify_anomaly(alert)
    assert "cavitation" in result
    assert "unauthorized write" in result


def test_classify_anomaly_write_only():
    alert = {
        "window_summary": {
            "tank_level_mean": 70.0,
            "has_write_fc": 1,
        }
    }
    result = _classify_anomaly(alert)
    assert "unauthorized Modbus write" in result
    assert "privilege escalation" in result


def test_classify_anomaly_overfill_with_scanning():
    alert = {
        "window_summary": {
            "function_codes": [3, 131],
            "tank_level_max": 92.2,
            "tank_level_mean": 60.0,
            "has_write_fc": 0,
        }
    }
    result = _classify_anomaly(alert)
    assert "overfill" in result
    assert "Modbus exception" in result


def test_classify_anomaly_scanning_only():
    alert = {
        "window_summary": {
            "function_codes": [3, 131],
            "tank_level_max": 40.0,
            "tank_level_mean": 35.0,
            "has_write_fc": 0,
        }
    }
    result = _classify_anomaly(alert)
    assert "FC 131" in result
    assert "scanning" in result


def test_classify_anomaly_overfill_only():
    alert = {
        "window_summary": {
            "function_codes": [3],
            "tank_level_max": 93.6,
            "tank_level_mean": 50.0,
            "has_write_fc": 0,
        }
    }
    result = _classify_anomaly(alert)
    assert "overfill" in result


def test_classify_anomaly_cavitation_only():
    alert = {
        "window_summary": {
            "function_codes": [3],
            "tank_level_max": 6.0,
            "tank_level_mean": 5.0,
            "has_write_fc": 0,
        }
    }
    result = _classify_anomaly(alert)
    assert "cavitation" in result


def test_classify_anomaly_generic():
    alert = {
        "window_summary": {
            "function_codes": [3],
            "tank_level_max": 55.0,
            "tank_level_mean": 45.0,
            "has_write_fc": 0,
        }
    }
    result = _classify_anomaly(alert)
    assert result == "OT process anomaly deviation"


# ---------------------------------------------------------------------------
# _build_query
# ---------------------------------------------------------------------------


def test_build_query_includes_expected_fields(write_alert):
    query = _build_query(write_alert)
    assert "172.21.0.10" in query
    assert "70.78" in query
    assert "172.24.0.10" in query
    assert "write observed: True" in query
    assert "privilege escalation" in query


def test_build_query_no_source_ips():
    alert = {
        "plc_ip": "172.21.0.10",
        "window_summary": {
            "tank_level_mean": 50.0,
            "tank_level_max": 60.0,
            "has_write_fc": 0,
            "source_ips": [],
            "function_codes": [3],
        },
    }
    query = _build_query(alert)
    assert "172.21.0.10" in query
    assert "function codes [3]" in query


# ---------------------------------------------------------------------------
# retrieve_context — mocked
# ---------------------------------------------------------------------------


def _make_mock_query_result(doc_texts):
    return {
        "documents": [doc_texts],
        "metadatas": [[{}] * len(doc_texts)],
        "distances": [[0.5] * len(doc_texts)],
        "ids": [[f"id_{i}" for i in range(len(doc_texts))]],
    }


def test_retrieve_context_returns_all_sections_with_mock_data(write_alert):
    mock_collection = MagicMock()

    def side_effect(query_texts, n_results, where):
        st = where["source_type"]
        if st == "asset":
            return _make_mock_query_result(
                ["## plc-intake (172.21.0.10)\nIntake PLC description"]
            )
        elif st == "control":
            return _make_mock_query_result(
                ["## Network Segmentation (SR 5.1)\nZone boundary"]
            )
        else:
            return _make_mock_query_result(
                ["## Incident 2024-11-12: Unauthorized Write\nWrite from 172.24.0.10"]
            )

    mock_collection.query.side_effect = side_effect

    with patch("src.rag._get_collection", return_value=mock_collection):
        result = retrieve_context(write_alert)

    assert "--- ASSET INFO ---" in result
    assert "--- IEC 62443 CONTROLS ---" in result
    assert "--- PAST INCIDENTS ---" in result
    assert "plc-intake" in result
    assert "SR 5.1" in result
    assert "Unauthorized Write" in result


def test_retrieve_context_graceful_empty_results(write_alert):
    mock_collection = MagicMock()

    empty = _make_mock_query_result([])
    mock_collection.query.return_value = empty

    with patch("src.rag._get_collection", return_value=mock_collection):
        result = retrieve_context(write_alert)

    assert result == "No relevant context found."
