"""Model and knowledge-base artifact integrity checks.

Pickled scikit-learn artifacts and a mutable vector store are supply-chain
inputs. We pin them with SHA-256 manifests and fail closed before loading.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.security.paths import PROJECT_ROOT

MODELS_DIR = PROJECT_ROOT / "models"
MODEL_MANIFEST = MODELS_DIR / "manifest.json"
RAG_DIR = PROJECT_ROOT / "data" / "rag_documents"
RAG_MANIFEST = RAG_DIR / "manifest.json"


class ArtifactIntegrityError(RuntimeError):
    """Raised when a model or knowledge-base artifact does not match its manifest."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_manifest(manifest_path: Path) -> dict[str, Any]:
    with open(manifest_path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or "manifest_version" not in data:
        raise ArtifactIntegrityError(f"invalid manifest: {manifest_path}")
    return data


def verify_manifest(
    base_dir: Path,
    manifest_path: Path,
    section: str = "artifacts",
    allow_extra: bool = False,
) -> list[str]:
    """Return a list of integrity errors (empty means verified)."""

    errors: list[str] = []
    if not manifest_path.is_file():
        return [f"manifest not found: {manifest_path}"]

    manifest = load_manifest(manifest_path)
    entries = manifest.get(section)
    if not isinstance(entries, dict) or not entries:
        return [f"manifest has no '{section}' entries"]

    for name, metadata in entries.items():
        path = base_dir / name
        if not path.is_file():
            errors.append(f"missing artifact: {name}")
            continue
        expected_sha = metadata.get("sha256")
        if not isinstance(expected_sha, str):
            errors.append(f"manifest entry has no sha256: {name}")
            continue
        actual_sha = sha256_file(path)
        if actual_sha != expected_sha:
            errors.append(f"sha256 mismatch: {name}")
        expected_bytes = metadata.get("bytes")
        if isinstance(expected_bytes, int) and path.stat().st_size != expected_bytes:
            errors.append(f"size mismatch: {name}")

    if not allow_extra:
        known = set(entries)
        for path in sorted(base_dir.iterdir()):
            if not path.is_file() or path.name == manifest_path.name:
                continue
            if path.name not in known:
                errors.append(f"unexpected artifact: {path.name}")

    return errors


def verify_model_artifacts(
    base_dir: Path | None = None, manifest_path: Path | None = None
) -> list[str]:
    return verify_manifest(
        base_dir or MODELS_DIR,
        manifest_path or MODEL_MANIFEST,
        section="artifacts",
    )


def verify_model_artifacts_or_raise(
    base_dir: Path | None = None, manifest_path: Path | None = None
) -> None:
    errors = verify_model_artifacts(base_dir, manifest_path)
    if errors:
        raise ArtifactIntegrityError("; ".join(errors))


def verify_rag_documents(
    base_dir: Path | None = None, manifest_path: Path | None = None
) -> list[str]:
    return verify_manifest(
        base_dir or RAG_DIR,
        manifest_path or RAG_MANIFEST,
        section="documents",
    )


def build_manifest(
    base_dir: Path,
    section: str,
    names: list[str] | None = None,
    metadata: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    entries: dict[str, Any] = {}
    for path in sorted(base_dir.iterdir()):
        if not path.is_file():
            continue
        if names is not None and path.name not in names:
            continue
        entry: dict[str, Any] = {
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        }
        if metadata and path.name in metadata:
            entry.update(metadata[path.name])
        entries[path.name] = entry
    return {
        "manifest_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        section: entries,
    }


def write_manifest(manifest_path: Path, manifest: dict[str, Any]) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
