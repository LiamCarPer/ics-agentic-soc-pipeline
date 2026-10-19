"""Generate a CycloneDX-style AI bill of materials (AI-BOM).

This is a lightweight, intentionally readable AI-BOM: model artifacts and
hashes, the embedding model, and the main libraries that shape model/prompt
behaviour. It is not a signed SBOM; see docs/AI_SECURITY.md for the limits.
"""

import json
import sys
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

_proj_root = Path(__file__).resolve().parent.parent
if str(_proj_root) not in sys.path:
    sys.path.insert(0, str(_proj_root))

from src.security.artifacts import (  # noqa: E402
    MODEL_MANIFEST,
    RAG_MANIFEST,
    load_manifest,
    sha256_file,
)

OUTPUT = _proj_root / "security" / "ai-bom.json"


def _version(package: str) -> str:
    try:
        return version(package)
    except PackageNotFoundError:
        return "unknown"


def _library(name: str) -> dict:
    return {"type": "library", "name": name, "version": _version(name)}


def main() -> None:
    model_manifest = load_manifest(MODEL_MANIFEST)
    rag_manifest = load_manifest(RAG_MANIFEST)
    model_entry = model_manifest["artifacts"]["isolation_forest.joblib"]

    components = [
        {
            "type": "machine-learning-model",
            "bom-ref": "model:isolation_forest",
            "name": "isolation_forest",
            "version": "sklearn-1.8.0",
            "hashes": [{"alg": "SHA-256", "content": model_entry["sha256"]}],
            "properties": [
                {"name": "purpose", "value": "OT process anomaly detection"},
                {
                    "name": "training_data_sha256",
                    "value": model_entry.get("training_data_sha256", "unknown"),
                },
                {
                    "name": "feature_set_sha256",
                    "value": model_entry.get("feature_set_sha256", "unknown"),
                },
                {"name": "trust_boundary", "value": "verified before joblib.load"},
            ],
        },
        {
            "type": "machine-learning-model",
            "bom-ref": "model:all-minilm-l6-v2",
            "name": "sentence-transformers/all-MiniLM-L6-v2",
            "version": f"sentence-transformers-{_version('sentence-transformers')}",
            "properties": [
                {"name": "purpose", "value": "local embedding model for RAG"},
                {
                    "name": "supply_chain_note",
                    "value": "downloaded at Docker build; pin a revision in production",
                },
            ],
        },
        {
            "type": "data",
            "bom-ref": "data:ot-soc-knowledge-base",
            "name": "ot-soc-knowledge-base",
            "version": "manifest-1",
            "hashes": [
                {
                    "alg": "SHA-256",
                    "content": sha256_file(RAG_MANIFEST),
                }
            ],
            "properties": [
                {
                    "name": "document_count",
                    "value": str(len(rag_manifest["documents"])),
                },
                {
                    "name": "trust_boundary",
                    "value": "SHA-256 verified before ingestion",
                },
            ],
        },
        _library("langchain"),
        _library("langchain-openai"),
        _library("openai"),
        _library("chromadb"),
        _library("scikit-learn"),
        _library("pandas"),
        _library("fastapi"),
        _library("pydantic"),
    ]

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "name": "ics-agentic-soc-pipeline",
                "version": "1.0.0",
            },
        },
        "components": components,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as handle:
        json.dump(bom, handle, indent=2)
        handle.write("\n")
    print(f"Wrote {OUTPUT} ({len(components)} components)")


if __name__ == "__main__":
    main()
