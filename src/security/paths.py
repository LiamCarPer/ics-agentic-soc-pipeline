"""Filesystem confinement for agent-generated artifacts."""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUTS_DIR = PROJECT_ROOT / "outputs"


def safe_output_path(filename: str, base: Path | str | None = None) -> Path:
    """Return a path inside ``base`` or raise ``ValueError``.

    The agent must never be able to choose a path outside the outputs
    directory. Filenames are flat (no separators), and the resolved path is
    checked against the resolved base to close traversal and symlink tricks.
    """

    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("filename must be a non-empty string")
    if "\x00" in filename:
        raise ValueError("filename must not contain NUL bytes")
    if "/" in filename or "\\" in filename:
        raise ValueError("filename must not contain path separators")
    if filename in {".", ".."}:
        raise ValueError("filename is not allowed")

    base_path = Path(base) if base is not None else OUTPUTS_DIR
    base_resolved = base_path.resolve()
    candidate = (base_resolved / filename).resolve()

    if candidate == base_resolved or not candidate.is_relative_to(base_resolved):
        raise ValueError("resolved path escapes the outputs directory")
    return candidate


def safe_output_dir(path: Path | str) -> Path:
    """Create and return an output directory, ensuring it is under PROJECT_ROOT."""

    resolved = Path(path).resolve()
    if not resolved.is_relative_to(PROJECT_ROOT.resolve()):
        raise ValueError("output directory must be inside the project root")
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved
