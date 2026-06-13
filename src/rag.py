"""RAG enrichment — retrieves context from ChromaDB for a given anomaly alert."""

from pathlib import Path

import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
CHROMA_PATH = _PROJECT_ROOT / "data" / "chromadb"
COLLECTION_NAME = "ot_soc_knowledge"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

_collection = None


def _get_collection():
    global _collection
    if _collection is None:
        client = chromadb.PersistentClient(str(CHROMA_PATH))
        embedding_fn = SentenceTransformerEmbeddingFunction(model_name=EMBEDDING_MODEL)
        _collection = client.get_collection(
            name=COLLECTION_NAME, embedding_function=embedding_fn
        )
    return _collection


def _build_query(alert: dict) -> str:
    plc_ip = alert.get("plc_ip", "unknown")
    summary = alert.get("window_summary", {})
    fcs = summary.get("function_codes", [])
    has_write = summary.get("has_write_fc", 0)
    tank_mean = summary.get("tank_level_mean", 0)
    src_ips = summary.get("source_ips", [])

    parts = [
        f"PLC at {plc_ip}",
        f"function codes {fcs}",
        f"tank level mean {tank_mean}%",
        f"write observed: {bool(has_write)}",
    ]
    if src_ips:
        parts.append(f"source IPs {src_ips}")
    return ". ".join(parts) + "."


def retrieve_context(alert: dict) -> str:
    collection = _get_collection()
    query = _build_query(alert)
    results = collection.query(query_texts=[query], n_results=5)

    sections = {"asset_inventory": [], "iec62443_controls": [], "past_incidents": []}

    if results["metadatas"] and results["documents"]:
        for meta, doc in zip(results["metadatas"][0], results["documents"][0]):
            source = meta.get("source", "")
            if source in sections:
                sections[source].append(doc)

    output_parts = []
    label_map = {
        "asset_inventory": "ASSET INFO",
        "iec62443_controls": "IEC 62443 CONTROLS",
        "past_incidents": "PAST INCIDENTS",
    }

    for key, label in label_map.items():
        if sections[key]:
            output_parts.append(f"--- {label} ---")
            output_parts.extend(sections[key])

    if not output_parts:
        return "No relevant context found."

    return "\n\n".join(output_parts)
