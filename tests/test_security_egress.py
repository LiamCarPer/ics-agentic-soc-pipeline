"""Tests for the LLM endpoint policy."""

import pytest

from src.security.egress import validate_llm_endpoint


def test_default_openai_is_allowed():
    assert validate_llm_endpoint(None) is None
    assert validate_llm_endpoint("https://api.openai.com/v1")


def test_openrouter_is_allowed():
    assert validate_llm_endpoint("https://openrouter.ai/api/v1")


def test_unexpected_host_is_rejected():
    with pytest.raises(ValueError, match="not allowlisted"):
        validate_llm_endpoint("https://attacker.example/v1")


def test_local_only_rejects_external_host():
    with pytest.raises(ValueError, match="local-only"):
        validate_llm_endpoint("https://api.openai.com/v1", local_only=True)


def test_local_only_allows_localhost():
    assert (
        validate_llm_endpoint("http://localhost:11434/v1", local_only=True)
        == "http://localhost:11434/v1"
    )


def test_allowed_hosts_env_extends_allowlist(monkeypatch):
    monkeypatch.setenv("ALLOWED_LLM_HOSTS", "internal-llm.example")
    assert (
        validate_llm_endpoint("https://internal-llm.example/v1")
        == "https://internal-llm.example/v1"
    )
