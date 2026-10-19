"""Tests for model and knowledge-base artifact integrity."""

import pytest

from src.security.artifacts import (
    ArtifactIntegrityError,
    build_manifest,
    verify_manifest,
    verify_model_artifacts,
    verify_model_artifacts_or_raise,
    verify_rag_documents,
    write_manifest,
)


def make_manifest(tmp_path, names=None):
    (tmp_path / "a.bin").write_text("alpha", encoding="utf-8")
    (tmp_path / "b.bin").write_text("beta", encoding="utf-8")
    manifest = build_manifest(tmp_path, "artifacts", names=names)
    manifest_path = tmp_path / "manifest.json"
    write_manifest(manifest_path, manifest)
    return manifest_path


def test_manifest_roundtrip(tmp_path):
    manifest_path = make_manifest(tmp_path, names=["a.bin", "b.bin"])
    assert verify_manifest(tmp_path, manifest_path) == []


def test_tampered_artifact_fails(tmp_path):
    manifest_path = make_manifest(tmp_path, names=["a.bin", "b.bin"])
    (tmp_path / "a.bin").write_text("tampered", encoding="utf-8")
    errors = verify_manifest(tmp_path, manifest_path)
    assert any("sha256 mismatch: a.bin" in error for error in errors)


def test_extra_artifact_fails_unless_allowed(tmp_path):
    manifest_path = make_manifest(tmp_path, names=["a.bin"])
    errors = verify_manifest(tmp_path, manifest_path)
    assert any("unexpected artifact: b.bin" in error for error in errors)
    assert verify_manifest(tmp_path, manifest_path, allow_extra=True) == []


def test_missing_artifact_fails(tmp_path):
    manifest_path = make_manifest(tmp_path, names=["a.bin", "b.bin"])
    (tmp_path / "b.bin").unlink()
    errors = verify_manifest(tmp_path, manifest_path)
    assert any("missing artifact: b.bin" in error for error in errors)


def test_missing_manifest_fails(tmp_path):
    errors = verify_manifest(tmp_path, tmp_path / "missing.json")
    assert errors and "manifest not found" in errors[0]


def test_committed_manifests_verify():
    assert verify_model_artifacts() == []
    assert verify_rag_documents() == []


def test_or_raise_fails_closed(tmp_path):
    manifest_path = make_manifest(tmp_path, names=["a.bin", "b.bin"])
    (tmp_path / "a.bin").write_text("tampered", encoding="utf-8")
    with pytest.raises(ArtifactIntegrityError):
        verify_model_artifacts_or_raise(tmp_path, manifest_path)
