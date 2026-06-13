# ICS Agentic SOC Analyst

## Detection Service

Run the anomaly detection pipeline from the command line:

```bash
python scripts/detect_anomalies.py \
  --input data/test/telemetry.csv \
  --output data/alerts.jsonl \
  --model models/isolation_forest.joblib \
  --scaler models/scaler.joblib
```

Optional arguments:
- `--window-size N` — sliding window size in rows (default: 6)
- `--stride N` — step between windows (default: 1)
- `--threshold FLOAT` — manual decision function cutoff; scores below this are flagged. If omitted, uses the model's default `predict()`.

