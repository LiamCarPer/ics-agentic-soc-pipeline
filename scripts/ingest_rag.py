"""
ingest_rag.py — Load, chunk, embed, and store RAG documents into ChromaDB.

Usage:
    python scripts/ingest_rag.py
    python scripts/ingest_rag.py --reset   # Rebuild from scratch

Steps:
    1. Read all markdown files from data/rag_documents/
    2. Split on ## headings to produce chunks
    3. Embed each chunk with all-MiniLM-L6-v2
    4. Store in ChromaDB collection "ot_soc_knowledge"
"""

import argparse
import re
import sys
from pathlib import Path

import chromadb
from chromadb.errors import NotFoundError
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAG_DIR = _PROJECT_ROOT / "data" / "rag_documents"
CHROMA_DIR = _PROJECT_ROOT / "data" / "chromadb"
COLLECTION_NAME = "ot_soc_knowledge"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"


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


def main():
    parser = argparse.ArgumentParser(
        description="Ingest RAG documents into ChromaDB."
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete existing collection and re-ingest from scratch",
    )
    args = parser.parse_args()

    if not RAG_DIR.exists():
        print(f"Error: RAG documents directory not found: {RAG_DIR}", file=sys.stderr)
        sys.exit(1)

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
        print(f"  {md_path.name}: {len(chunks)} chunks")

        for i, (content, heading) in enumerate(chunks):
            doc_id = f"{md_path.stem}_{i:03d}"
            documents.append(content)
            metadatas.append(
                {
                    "source": md_path.stem,
                    "section": heading,
                    "file": md_path.name,
                }
            )
            ids.append(doc_id)

    collection.add(documents=documents, metadatas=metadatas, ids=ids)
    print(
        f"\nInserted {len(documents)} chunks into collection "
        f"'{COLLECTION_NAME}' (ChromaDB at {CHROMA_DIR})"
    )

    result = collection.query(query_texts=["plc intake unauthorized modbus write"], n_results=3)
    print("\nSanity check query 'plc intake unauthorized modbus write':")
    for doc in result["documents"][0]:
        print(f"  - {doc[:100]}...")


if __name__ == "__main__":
    main()
