"""Poisoning experiment: adding attack-shaped windows to "normal" training data.

An attacker who can contribute telemetry can teach the model that dangerous
process states are normal. We generate separate corpora with the same generator
(different seeds), add a fraction of their cavitation and scanning windows to
the normal training set, retrain the Isolation Forest, and measure per-class
recall on the clean committed test set. Results are averaged over several draws
to reduce threshold noise.

Run:
    python security/evals/poisoning_experiment.py
"""

import argparse
import subprocess
import sys
import tempfile
import warnings
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

_proj_root = Path(__file__).resolve().parent.parent.parent
if str(_proj_root) not in sys.path:
    sys.path.insert(0, str(_proj_root))

from src.features import build_windowed_features  # noqa: E402
from src.security.artifacts import (  # noqa: E402
    MODELS_DIR,
    sha256_file,
    verify_model_artifacts_or_raise,
)

CLASSES = [
    "overfill",
    "unauthorized_write",
    "scanning",
    "physics_violation",
    "cavitation",
]
POISON_CLASSES = {"cavitation", "scanning"}
SEEDS = [7, 11, 13, 17, 19]
TRIALS = 10


def annotated_windows(
    telemetry: pd.DataFrame, annotations: pd.DataFrame
) -> tuple[pd.DataFrame, dict[int, set[str]]]:
    features, timestamps = build_windowed_features(telemetry)
    labels: dict[int, set[str]] = {}
    for index, timestamp in enumerate(timestamps):
        types = {
            annotation.anomaly_type
            for _, annotation in annotations.iterrows()
            if annotation.start_time <= timestamp <= annotation.end_time
        }
        if types:
            labels[index] = types
    return features, labels


def generate_corpus(directory: Path, seed: int) -> tuple[pd.DataFrame, pd.DataFrame]:
    subprocess.run(
        [
            sys.executable,
            str(_proj_root / "scripts" / "generate_telemetry.py"),
            "--duration",
            "1200",
            "--schedule",
            str(_proj_root / "scripts" / "schedule_test.json"),
            "--fast",
            "--seed",
            str(seed),
            "--output",
            str(directory),
        ],
        check=True,
        cwd=_proj_root,
        stdout=subprocess.DEVNULL,
    )
    telemetry = pd.read_csv(directory / "telemetry.csv", parse_dates=["timestamp"])
    annotations = pd.read_csv(
        directory / "annotations.csv", parse_dates=["start_time", "end_time"]
    )
    telemetry.sort_values("timestamp", inplace=True)
    return telemetry, annotations


def evaluate(model, scaler, x_test, y_test, label_map) -> dict:
    predictions = (model.predict(scaler.transform(x_test)) == -1).astype(int)
    per_class = {}
    for anomaly_type in CLASSES:
        indices = [index for index, types in label_map.items() if anomaly_type in types]
        per_class[anomaly_type] = (
            sum(predictions[index] for index in indices) / len(indices)
            if indices
            else 0.0
        )
    return {
        "precision": precision_score(y_test, predictions, zero_division=0),
        "recall": recall_score(y_test, predictions, zero_division=0),
        "f1": f1_score(y_test, predictions, zero_division=0),
        "per_class": per_class,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure training-data poisoning.")
    parser.add_argument(
        "--output",
        type=Path,
        default=_proj_root / "security" / "evals" / "poisoning_results.md",
    )
    parser.add_argument(
        "--rates", type=str, default="0,0.01,0.05,0.10,0.20", help="Poison fractions"
    )
    args = parser.parse_args()
    rates = [float(value) for value in args.rates.split(",") if value.strip()]

    verify_model_artifacts_or_raise()

    train = pd.read_csv(
        _proj_root / "data" / "train" / "telemetry.csv", parse_dates=["timestamp"]
    ).sort_values("timestamp")
    test = pd.read_csv(
        _proj_root / "data" / "test" / "telemetry.csv", parse_dates=["timestamp"]
    ).sort_values("timestamp")
    test_annotations = pd.read_csv(
        _proj_root / "data" / "test" / "annotations.csv",
        parse_dates=["start_time", "end_time"],
    )

    x_train, _ = annotated_windows(
        train, pd.DataFrame(columns=["start_time", "end_time", "anomaly_type"])
    )
    x_test, label_map = annotated_windows(test, test_annotations)
    y_test = [1 if index in label_map else 0 for index in range(len(x_test))]

    poison_frames = []
    with tempfile.TemporaryDirectory() as tmp:
        for seed in SEEDS:
            seed_dir = Path(tmp) / f"seed_{seed}"
            seed_dir.mkdir()
            telemetry, annotations = generate_corpus(seed_dir, seed)
            features, labels = annotated_windows(telemetry, annotations)
            indices = [
                index for index, types in labels.items() if types & POISON_CLASSES
            ]
            poison_frames.append(features.iloc[indices].reset_index(drop=True))
    poison_pool = pd.concat(poison_frames, ignore_index=True)

    results = []
    for rate in rates:
        count = int(round(len(x_train) * rate))
        metrics = []
        if count == 0:
            metrics.append(
                _fit_and_evaluate(x_train, x_test, y_test, label_map, x_train.iloc[0:0])
            )
        else:
            for trial in range(TRIALS):
                sample = poison_pool.sample(
                    n=min(count, len(poison_pool)), random_state=100 + trial
                ).reset_index(drop=True)
                metrics.append(
                    _fit_and_evaluate(x_train, x_test, y_test, label_map, sample)
                )

        averaged = {
            "rate": rate,
            "added": count,
            "precision": _mean(metrics, "precision"),
            "recall": _mean(metrics, "recall"),
            "f1": _mean(metrics, "f1"),
            "per_class": {
                anomaly_type: _mean_per_class(metrics, anomaly_type)
                for anomaly_type in CLASSES
            },
        }
        results.append(averaged)

    header = [
        "# Training-data poisoning results",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Committed model SHA-256: `{sha256_file(MODELS_DIR / 'isolation_forest.joblib')[:16]}…`",
        "",
        f"Poison pool: {len(poison_pool)} cavitation/scanning windows from "
        f"{len(SEEDS)} separately generated corpora (seeds "
        f"{', '.join(str(seed) for seed in SEEDS)}). Each rate is averaged over "
        f"{TRIALS} random draws. Scaler and Isolation Forest are retrained on "
        "normal + poison; evaluation is on the clean `data/test` set (20 "
        "anomaly windows).",
        "",
        "| Poison rate | Added windows | Precision | Recall | F1 | Cavitation | Scanning | Physics | Overfill | Write |",
        "| --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |",
    ]
    table = []
    for result in results:
        per_class = result["per_class"]
        table.append(
            f"| {result['rate']:.0%} | {result['added']} | "
            f"{result['precision']:.3f} | {result['recall']:.3f} | "
            f"{result['f1']:.3f} | "
            f"{per_class['cavitation']:.0%} | {per_class['scanning']:.0%} | "
            f"{per_class['physics_violation']:.0%} | "
            f"{per_class['overfill']:.0%} | "
            f"{per_class['unauthorized_write']:.0%} |"
        )

    interpretation = [
        "",
        "## Interpretation",
        "",
        "- Adding anomaly-shaped windows to the normal class teaches the model "
        "that those states are benign. Per-class recall for the poisoned "
        "classes falls as the poison fraction rises.",
        "- Overfill and unauthorized writes are already missed by the baseline, "
        "so poisoning cannot reduce their recall further — a class the model "
        "never learned is not protected by anomaly detection.",
        "- Defence: provenance and review of training telemetry, labelled "
        "holdouts, drift monitoring, and physics invariants that do not depend "
        "on training data.",
        "- Limits: the attacker is assumed to influence the training set; the "
        "poison is drawn from the same simulator; the averages reduce but do "
        "not eliminate threshold noise from a small dataset.",
        "",
    ]

    output = "\n".join(header + table + interpretation)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(output, encoding="utf-8")
    print("\n".join(header[:1] + table))
    print(f"\nWrote {args.output}")


def _fit_and_evaluate(x_train, x_test, y_test, label_map, poison) -> dict:
    combined = pd.concat([x_train.reset_index(drop=True), poison], ignore_index=True)
    scaler = StandardScaler()
    scaled = scaler.fit_transform(combined)
    model = IsolationForest(contamination=0.01, random_state=42, n_estimators=100).fit(
        scaled
    )
    return evaluate(model, scaler, x_test, y_test, label_map)


def _mean(metrics, key: str) -> float:
    return sum(metric[key] for metric in metrics) / len(metrics)


def _mean_per_class(metrics, anomaly_type: str) -> float:
    return sum(metric["per_class"][anomaly_type] for metric in metrics) / len(metrics)


if __name__ == "__main__":
    main()
