"""
ingest_rag.py — Load, chunk, embed, and store RAG documents into ChromaDB.

Usage:
    python scripts/ingest_rag.py
    python scripts/ingest_rag.py --reset          # Rebuild from scratch
    python scripts/ingest_rag.py --update-manifest
    python scripts/ingest_rag.py --allow-unverified   # Local development only

Security:
    The knowledge base is a supply-chain input. Every document is pinned in
    data/rag_documents/manifest.json by SHA-256 and verified before ingestion.
    Unknown or modified documents fail closed. Instruction-like text is flagged
    for review (a heuristic, not a prompt-injection control).
"""

import argparse
import sys
from pathlib import Path

import chromadb
from chromadb.errors import NotFoundError
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

_proj_root = Path(__file__).resolve().parent.parent
if str(_proj_root) not in sys.path:
    sys.path.insert(0, str(_proj_root))

from src.security.artifacts import (  # noqa: E402
    build_manifest,
    sha256_file,
    verify_rag_documents,
    write_manifest,
)
from src.security.sanitize import detect_instruction_patterns  # noqa: E402

RAG_DIR = _proj_root / "data" / "rag_documents"
CHROMA_DIR = _proj_root / "data" / "chromadb"
MANIFEST_PATH = RAG_DIR / "manifest.json"
COLLECTION_NAME = "ot_soc_knowledge"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

SOURCE_TYPE_MAP = {
    "asset_inventory": ("asset", "plc ip zone firmware asset ot device"),
    "iec62443_controls": (
        "control",
        "iec 62443 security control standard requirement",
    ),
    "past_incidents": ("incident", "past incident report anomaly attack response"),
}


def chunk_markdown(text: str, source_file: str):
    lines = text.split("\n")
    chunks = []
    current_heading = None
    current_body = []

    def flush():
        nonlocal current_heading, current_body
        if current_heading is not None:
            content = (current_heading + "\n" + "\n".join(current_body)).strip()
            if len(content) > 20:
                chunks.append((content, current_heading))
        current_heading = None
        current_body = []

    for line in lines:
        if line.startswith("## "):
            flush()
            current_heading = line
        else:
            if current_heading is None:
                if line.strip():
                    current_heading = source_file
                    current_body.append(line)
            else:
                current_body.append(line)

    flush()
    return chunks


def update_manifest() -> None:
    md_files = sorted(RAG_DIR.glob("*.md"))
    manifest = build_manifest(
        RAG_DIR, "documents", names=[path.name for path in md_files]
    )
    for path in md_files:
        source_type, _ = SOURCE_TYPE_MAP.get(path.stem, ("unknown", "ot security"))
        manifest["documents"][path.name]["source_type"] = source_type
    write_manifest(MANIFEST_PATH, manifest)
    print(f"Wrote manifest for {len(md_files)} documents to {MANIFEST_PATH}")


def verify_documents(allow_unverified: bool) -> None:
    if not MANIFEST_PATH.exists():
        if allow_unverified:
            print("WARNING: no RAG manifest; continuing because --allow-unverified")
            return
        print(
            f"Error: missing RAG manifest {MANIFEST_PATH}. "
            "Run with --update-manifest after reviewing document changes.",
            file=sys.stderr,
        )
        sys.exit(1)

    if allow_unverified:
        print("WARNING: skipping RAG provenance verification (--allow-unverified)")
        return

    errors = verify_rag_documents()
    if errors:
        for error in errors:
            print(f"Error: {error}", file=sys.stderr)
        print(
            "Refusing to ingest unverified knowledge-base documents. "
            "Review the changes, then run --update-manifest.",
            file=sys.stderr,
        )
        sys.exit(1)
    print("Verified RAG document manifest.")


def main():
    parser = argparse.ArgumentParser(description="Ingest RAG documents into ChromaDB.")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete existing collection and re-ingest from scratch",
    )
    parser.add_argument(
        "--update-manifest",
        action="store_true",
        help="Recompute document hashes in data/rag_documents/manifest.json",
    )
    parser.add_argument(
        "--allow-unverified",
        action="store_true",
        help="Skip provenance verification (local development only)",
    )
    args = parser.parse_args()

    if not RAG_DIR.exists():
        print(f"Error: RAG documents directory not found: {RAG_DIR}", file=sys.stderr)
        sys.exit(1)

    if args.update_manifest:
        update_manifest()
    verify_documents(args.allow_unverified)

    client = chromadb.PersistentClient(str(CHROMA_DIR))

    if args.reset:
        try:
            client.delete_collection(COLLECTION_NAME)
            print(f"Deleted existing collection '{COLLECTION_NAME}'")
        except NotFoundError:
            pass

    embedding_fn = SentenceTransformerEmbeddingFunction(model_name=EMBEDDING_MODEL)
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME, embedding_function=embedding_fn
    )

    existing_count = collection.count()
    if existing_count > 0 and not args.reset:
        print(
            f"Collection '{COLLECTION_NAME}' already has {existing_count} chunks. "
            f"Use --reset to re-ingest."
        )
        return

    documents = []
    metadatas = []
    ids = []

    md_files = sorted(RAG_DIR.glob("*.md"))
    if not md_files:
        print(f"Error: no markdown files found in {RAG_DIR}", file=sys.stderr)
        sys.exit(1)

    for md_path in md_files:
        text = md_path.read_text(encoding="utf-8")
        chunks = chunk_markdown(text, md_path.stem)
        source_type, default_keywords = SOURCE_TYPE_MAP.get(
            md_path.stem, ("unknown", "ot security")
        )
        suspicious = detect_instruction_patterns(text)
        if suspicious:
            print(
                f"  WARNING: {md_path.name} contains instruction-like text "
                f"({', '.join(suspicious)}); review before use."
            )
        print(f"  {md_path.name}: {len(chunks)} chunks")

        for i, (content, heading) in enumerate(chunks):
            doc_id = f"{md_path.stem}_{i:03d}"
            documents.append(content)
            metadatas.append(
                {
                    "source": md_path.stem,
                    "source_type": source_type,
                    "section": heading,
                    "file": md_path.name,
                    "keywords": default_keywords,
                    "source_sha256": sha256_file(md_path),
                    "suspicious_patterns": ", ".join(suspicious),
                }
            )
            ids.append(doc_id)

    collection.add(documents=documents, metadatas=metadatas, ids=ids)
    print(
        f"\nInserted {len(documents)} chunks into collection "
        f"'{COLLECTION_NAME}' (ChromaDB at {CHROMA_DIR})"
    )

    result = collection.query(
        query_texts=["plc intake unauthorized modbus write"], n_results=3
    )
    print("\nSanity check query 'plc intake unauthorized modbus write':")
    for doc in result["documents"][0]:
        print(f"  - {doc[:100]}...")


if __name__ == "__main__":
    main()
