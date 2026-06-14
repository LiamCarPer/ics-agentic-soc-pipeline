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


def _classify_anomaly(alert: dict) -> str:
    summary = alert.get("window_summary", {})
    fcs = summary.get("function_codes", [])
    has_write = summary.get("has_write_fc", 0)
    tank_max = summary.get("tank_level_max", 0)
    tank_mean = summary.get("tank_level_mean", 0)

    if has_write == 1 and tank_mean < 10:
        return (
            "cavitation risk pump damage low tank level rapid drop unauthorized write"
        )
    if has_write == 1:
        return "unauthorized Modbus write command function code 6 privilege escalation"
    if 131 in fcs and tank_max > 80:
        return "tank overfill high water level critical overflow Modbus exception"
    if 131 in fcs:
        return "Modbus exception response FC 131 network scanning reconnaissance"
    if tank_max > 90:
        return "tank overfill high water level critical overflow"
    if tank_mean < 15:
        return "cavitation risk low tank level process anomaly"
    return "OT process anomaly deviation"


def _build_query(alert: dict) -> str:
    plc_ip = alert.get("plc_ip", "unknown")
    summary = alert.get("window_summary", {})
    fcs = summary.get("function_codes", [])
    has_write = summary.get("has_write_fc", 0)
    tank_mean = summary.get("tank_level_mean", 0)
    src_ips = summary.get("source_ips", [])
    anomaly_desc = _classify_anomaly(alert)

    parts = [
        f"PLC at {plc_ip}",
        f"function codes {fcs}",
        f"tank level mean {tank_mean}%",
        f"write observed: {bool(has_write)}",
        anomaly_desc,
    ]
    if src_ips:
        parts.append(f"source IPs {src_ips}")
    return ". ".join(parts) + "."


def retrieve_context(alert: dict) -> str:
    collection = _get_collection()
    query = _build_query(alert)

    asset_results = collection.query(
        query_texts=[query], n_results=2, where={"source_type": "asset"}
    )
    control_results = collection.query(
        query_texts=[query], n_results=2, where={"source_type": "control"}
    )
    incident_results = collection.query(
        query_texts=[query], n_results=1, where={"source_type": "incident"}
    )

    sections = {
        "ASSET INFO": asset_results["documents"][0]
        if asset_results["documents"]
        else [],
        "IEC 62443 CONTROLS": control_results["documents"][0]
        if control_results["documents"]
        else [],
        "PAST INCIDENTS": incident_results["documents"][0]
        if incident_results["documents"]
        else [],
    }

    output_parts = []
    for label, docs in sections.items():
        if docs:
            output_parts.append(f"--- {label} ---")
            output_parts.extend(docs)

    if not output_parts:
        return "No relevant context found."

    return "\n\n".join(output_parts)
