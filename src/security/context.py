"""Per-run context for the agent tools.

Tools must not trust the LLM for values that already exist in the alert. The
runner registers the validated alert and the retrieved RAG context here; tools
look them up by ``alert_id``. This removes prompt-supplied RAG text and IPs from
the tool boundary.
"""

from __future__ import annotations

import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

from src.security.guards import canonical_uuid
from src.security.paths import OUTPUTS_DIR

_MAX_CONTEXTS = 64


@dataclass(frozen=True)
class RunContext:
    alert_id: str
    alert: dict
    rag_context: str
    rag_ids: tuple[str, ...]
    output_dir: Path
    run_id: str


_LOCK = threading.Lock()
_CONTEXTS: "OrderedDict[str, RunContext]" = OrderedDict()


def register_run_context(
    alert: dict,
    rag_context: str,
    rag_ids: tuple[str, ...] | list[str] = (),
    output_dir: Path | str | None = None,
    run_id: str | None = None,
) -> RunContext:
    alert_id = canonical_uuid(alert.get("alert_id", ""))
    resolved_output = Path(output_dir) if output_dir is not None else OUTPUTS_DIR
    resolved_output.mkdir(parents=True, exist_ok=True)

    context = RunContext(
        alert_id=alert_id,
        alert=alert,
        rag_context=rag_context,
        rag_ids=tuple(rag_ids),
        output_dir=resolved_output,
        run_id=run_id or str(uuid.uuid4()),
    )

    with _LOCK:
        _CONTEXTS[alert_id] = context
        _CONTEXTS.move_to_end(alert_id)
        while len(_CONTEXTS) > _MAX_CONTEXTS:
            _CONTEXTS.popitem(last=False)
    return context


def get_run_context(alert_id: str) -> RunContext | None:
    try:
        canonical = canonical_uuid(alert_id)
    except ValueError:
        return None
    with _LOCK:
        return _CONTEXTS.get(canonical)


def clear_run_context(alert_id: str) -> None:
    try:
        canonical = canonical_uuid(alert_id)
    except ValueError:
        return
    with _LOCK:
        _CONTEXTS.pop(canonical, None)


def clear_all() -> None:
    with _LOCK:
        _CONTEXTS.clear()
