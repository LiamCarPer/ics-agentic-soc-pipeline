"""Verify model and knowledge-base artifact integrity. Exits non-zero on drift."""

import argparse
import json
import sys
from pathlib import Path

_proj_root = Path(__file__).resolve().parent.parent
if str(_proj_root) not in sys.path:
    sys.path.insert(0, str(_proj_root))

from src.security.artifacts import (  # noqa: E402
    verify_model_artifacts,
    verify_rag_documents,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify artifact integrity.")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args()

    errors = verify_model_artifacts() + verify_rag_documents()
    if args.json:
        print(json.dumps({"ok": not errors, "errors": errors}, indent=2))
    elif errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
    else:
        print("OK: model and RAG artifacts match their manifests.")

    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
