"""Regenerate model and knowledge-base integrity manifests.

Run this only after an intentional retrain or an approved document update.
The security posture is fail-closed: the pipeline will not load artifacts or
ingest documents whose hashes do not match the committed manifest.
"""

import argparse
import sys
from pathlib import Path

_proj_root = Path(__file__).resolve().parent.parent
if str(_proj_root) not in sys.path:
    sys.path.insert(0, str(_proj_root))

from src.features import FEATURE_COLUMNS  # noqa: E402
from src.security.artifacts import (  # noqa: E402
    MODEL_MANIFEST,
    MODELS_DIR,
    RAG_DIR,
    RAG_MANIFEST,
    build_manifest,
    sha256_file,
    sha256_text,
    write_manifest,
)

MODEL_FILES = ["isolation_forest.joblib", "scaler.joblib"]
TRAINING_DATA = _proj_root / "data" / "train" / "telemetry.csv"


def main() -> None:
    parser = argparse.ArgumentParser(description="Regenerate artifact manifests.")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm that the artifact changes are intentional and reviewed.",
    )
    args = parser.parse_args()

    if not args.yes:
        print(
            "Refusing to update manifests without --yes. Review the changed "
            "model/documents first; updating a manifest after tampering defeats "
            "the integrity check.",
            file=sys.stderr,
        )
        sys.exit(1)

    training_hash = (
        sha256_file(TRAINING_DATA) if TRAINING_DATA.is_file() else "unavailable"
    )
    feature_hash = sha256_text(",".join(FEATURE_COLUMNS))

    model_manifest = build_manifest(
        MODELS_DIR,
        "artifacts",
        names=MODEL_FILES,
        metadata={
            "isolation_forest.joblib": {
                "role": "anomaly-detector",
                "trained_with_sklearn": "1.8.0",
                "training_data": "data/train/telemetry.csv",
                "training_data_sha256": training_hash,
                "feature_set_sha256": feature_hash,
                "hyperparameters": {
                    "contamination": 0.01,
                    "n_estimators": 100,
                    "random_state": 42,
                },
            },
            "scaler.joblib": {
                "role": "preprocessor",
                "trained_with_sklearn": "1.8.0",
                "training_data_sha256": training_hash,
                "feature_set_sha256": feature_hash,
            },
        },
    )
    write_manifest(MODEL_MANIFEST, model_manifest)
    print(f"Wrote {MODEL_MANIFEST}")

    md_files = sorted(RAG_DIR.glob("*.md"))
    rag_manifest = build_manifest(
        RAG_DIR, "documents", names=[path.name for path in md_files]
    )
    for path in md_files:
        rag_manifest["documents"][path.name]["source"] = "ot-soc-knowledge-base"
    write_manifest(RAG_MANIFEST, rag_manifest)
    print(f"Wrote {RAG_MANIFEST} ({len(md_files)} documents)")


if __name__ == "__main__":
    main()
