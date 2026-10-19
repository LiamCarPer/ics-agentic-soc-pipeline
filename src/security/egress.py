"""LLM endpoint policy: provider allowlist and local-only mode."""

from __future__ import annotations

import os
from urllib.parse import urlparse

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "host.docker.internal"})
DEFAULT_ALLOWED_HOSTS = frozenset({"api.openai.com", "openrouter.ai"}) | LOOPBACK_HOSTS


def _endpoint_host(base_url: str | None) -> str:
    if not base_url:
        return "api.openai.com"
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"invalid LLM base URL: {base_url!r}")
    return parsed.hostname.lower()


def allowed_hosts() -> set[str]:
    configured = os.environ.get("ALLOWED_LLM_HOSTS", "")
    extra = {item.strip().lower() for item in configured.split(",") if item.strip()}
    return set(DEFAULT_ALLOWED_HOSTS) | extra


def validate_llm_endpoint(base_url: str | None, local_only: bool = False) -> str | None:
    """Reject unexpected LLM endpoints and enforce local-only mode."""

    host = _endpoint_host(base_url)
    if local_only and host not in LOOPBACK_HOSTS:
        raise ValueError(f"local-only mode rejects non-local LLM host: {host}")
    if host not in allowed_hosts():
        raise ValueError(
            f"LLM host {host!r} is not allowlisted; set ALLOWED_LLM_HOSTS to override"
        )
    return base_url
