"""
detect_anomalies.py — Production anomaly detection service.

Ingests a telemetry CSV, applies windowed feature engineering,
scores each window with a trained Isolation Forest, and emits
structured JSON Lines alerts for downstream consumers (RAG, Agent).

Usage:
    python scripts/detect_anomalies.py \\
        --input data/test/telemetry.csv \\
        --output data/alerts.jsonl \\
        --model models/isolation_forest.joblib \\
        --scaler models/scaler.joblib \\
        --window-size 6 \\
        --stride 1 \\
        --threshold -0.03

If --threshold is omitted, the model's default contamination-based
predict() is used.  --threshold enables manual tuning of the
decision_function cutoff as documented in FEATURE_ENGINEERING.md.
"""

import argparse
import json
import sys
import uuid
from pathlib import Path

# Ensure project root is on sys.path so `from src.features` works
# regardless of which directory the script is invoked from.
_proj_root = Path(__file__).resolve().parent.parent
if str(_proj_root) not in sys.path:
    sys.path.insert(0, str(_proj_root))

import pandas as pd

from src.features import build_windowed_features

PLC_ID = "plc_intake"
PLC_IP = "172.21.0.10"


def load_model_and_scaler(model_path: Path, scaler_path: Path):
    import joblib

    if not model_path.exists():
        print(f"Error: model file not found: {model_path}", file=sys.stderr)
        sys.exit(1)
    if not scaler_path.exists():
        print(f"Error: scaler file not found: {scaler_path}", file=sys.stderr)
        sys.exit(1)

    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    return model, scaler


def load_telemetry(input_path: Path) -> pd.DataFrame:
    if not input_path.exists():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    df = pd.read_csv(input_path, parse_dates=["timestamp"])
    if df.empty:
        print(f"Error: input file is empty: {input_path}", file=sys.stderr)
        sys.exit(1)

    df.sort_values("timestamp", inplace=True)
    return df


def build_alert(
    window_df: pd.DataFrame,
    window_feats: dict,
    anomaly_score: float,
    window_start_ts,
    window_end_ts,
) -> dict:
    raw_rows = window_df.drop(columns=["timestamp"]).to_dict(orient="records")

    return {
        "alert_id": str(uuid.uuid4()),
        "timestamp": window_end_ts.isoformat(),
        "plc_id": PLC_ID,
        "plc_ip": PLC_IP,
        "anomaly_score": round(anomaly_score, 6),
        "window_start": window_start_ts.isoformat(),
        "window_end": window_end_ts.isoformat(),
        "window_summary": {
            "tank_level_mean": round(window_feats["tank_mean"], 2),
            "tank_level_max": round(window_feats["tank_max"], 2),
            "has_write_fc": int(window_feats["has_write_fc"]),
            "source_ips": list(window_df["source_ip"].unique()),
            "function_codes": sorted(window_df["function_code"].unique().tolist()),
        },
        "raw_data": raw_rows,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Detect anomalies in OT telemetry using a trained Isolation Forest."
    )
    parser.add_argument(
        "--input", required=True, type=str, help="Path to telemetry CSV"
    )
    parser.add_argument(
        "--output", required=True, type=str, help="Path for alerts.jsonl output"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="models/isolation_forest.joblib",
        help="Path to trained IsolationForest model (default: models/isolation_forest.joblib)",
    )
    parser.add_argument(
        "--scaler",
        type=str,
        default="models/scaler.joblib",
        help="Path to fitted StandardScaler (default: models/scaler.joblib)",
    )
    parser.add_argument(
        "--window-size",
        type=int,
        default=6,
        help="Number of rows per sliding window (default: 6)",
    )
    parser.add_argument(
        "--stride",
        type=int,
        default=1,
        help="Step size between windows (default: 1)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help=(
            "Decision function threshold. Windows with score below this "
            "value are flagged. If omitted, model.predict() is used."
        ),
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    model_path = Path(args.model)
    scaler_path = Path(args.scaler)

    df = load_telemetry(input_path)
    model, scaler = load_model_and_scaler(model_path, scaler_path)

    X_features, timestamps = build_windowed_features(
        df, window_size=args.window_size, stride=args.stride
    )

    X_scaled = scaler.transform(X_features)
    scores = model.decision_function(X_scaled)

    if args.threshold is not None:
        anomaly_flags = scores < args.threshold
        method = f"threshold={args.threshold}"
    else:
        anomaly_flags = model.predict(X_scaled) == -1
        method = "model.predict()"

    # Build alerts for anomalous windows
    alerts = []
    for idx in range(len(X_features)):
        if not anomaly_flags[idx]:
            continue

        window_start_idx = idx * args.stride
        window_end_idx = window_start_idx + args.window_size
        window_df = df.iloc[window_start_idx:window_end_idx]

        feats = X_features.iloc[idx].to_dict()
        alert = build_alert(
            window_df=window_df,
            window_feats=feats,
            anomaly_score=scores[idx],
            window_start_ts=df.iloc[window_start_idx]["timestamp"],
            window_end_ts=df.iloc[window_end_idx - 1]["timestamp"],
        )
        alerts.append(alert)

    # Write output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        for alert in alerts:
            f.write(json.dumps(alert, default=str) + "\n")

    n_windows = len(X_features)
    n_flagged = anomaly_flags.sum()
    print(
        f"Processed {n_windows} windows, flagged {n_flagged} anomalies "
        f"(method: {method}), output written to {output_path}"
    )


if __name__ == "__main__":
    main()
