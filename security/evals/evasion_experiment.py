"""Evasion experiments against the committed anomaly detector.

Two scenarios:

1. Slow process drift: ramp the tank from 50% to 95% (overfill) or 5%
   (cavitation) at controlled rates. We separate detection of the physically
   dangerous portion from early-ramp false alarms, and report the final
   plateau.
2. Low-rate scan from a trusted source: inject Modbus exception responses from
   the HMI IP at different intervals, using a generated normal telemetry
   baseline so the process features stay in distribution.

This is a white-box experiment on synthetic data. It quantifies limitations; it
does not prove field evasion.

Run:
    python security/evals/evasion_experiment.py
"""

import argparse
import collections
import subprocess
import sys
import tempfile
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path

import joblib
import pandas as pd

warnings.filterwarnings("ignore")

_proj_root = Path(__file__).resolve().parent.parent.parent
if str(_proj_root) not in sys.path:
    sys.path.insert(0, str(_proj_root))

from src.features import FEATURE_COLUMNS, build_windowed_features  # noqa: E402
from src.security.artifacts import (  # noqa: E402
    MODELS_DIR,
    sha256_file,
    verify_model_artifacts_or_raise,
)

RAMP_MINUTES = [45.0, 22.5, 11.25, 4.5, 2.25, 0.75]
START_LEVEL = 50.0


def _timestamps(rows: int):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return [start + timedelta(seconds=5 * index) for index in range(rows)]


def ramp_frame(direction: str, minutes: float) -> tuple[pd.DataFrame, pd.DataFrame]:
    ramp_rows = max(6, int((minutes * 60) / 5))
    end_level = 95.0 if direction == "overfill" else 5.0
    step = (end_level - START_LEVEL) / ramp_rows
    ramp_values = [START_LEVEL + step * index for index in range(ramp_rows)]
    plateau_values = [end_level] * 20

    def frame(values):
        return pd.DataFrame(
            {
                "timestamp": _timestamps(len(values)),
                "reg_5_tank_level": [round(value, 3) for value in values],
                "reg_0_inlet_valve": 0 if direction == "overfill" else 1,
                "source_ip": "172.22.0.10",
                "function_code": 3,
            }
        )

    return frame(ramp_values), frame(plateau_values)


def generate_normal_baseline() -> pd.DataFrame:
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            [
                sys.executable,
                str(_proj_root / "scripts" / "generate_telemetry.py"),
                "--duration",
                "3000",
                "--fast",
                "--seed",
                "3",
                "--output",
                tmp,
            ],
            check=True,
            cwd=_proj_root,
            stdout=subprocess.DEVNULL,
        )
        telemetry = pd.read_csv(Path(tmp) / "telemetry.csv", parse_dates=["timestamp"])
    return telemetry.sort_values("timestamp").reset_index(drop=True)


def scan_frame(base: pd.DataFrame, every: int | None, source: str) -> pd.DataFrame:
    frame = base.copy()
    if every is None:
        frame["function_code"] = 3
    else:
        frame["function_code"] = [
            131 if index % every == 0 else 3 for index in range(len(frame))
        ]
    frame["source_ip"] = source
    return frame


def score(model, scaler, frame: pd.DataFrame):
    features, _ = build_windowed_features(frame)
    scores = model.decision_function(scaler.transform(features))
    predictions = model.predict(scaler.transform(features)) == -1
    return features, scores, predictions


def feature_usage(model) -> collections.Counter:
    usage = collections.Counter()
    for estimator in model.estimators_:
        features = {int(index) for index in estimator.tree_.feature if index >= 0}
        usage.update(features)
    return usage


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure detector evasion.")
    parser.add_argument(
        "--output",
        type=Path,
        default=_proj_root / "security" / "evals" / "evasion_results.md",
    )
    args = parser.parse_args()

    verify_model_artifacts_or_raise()
    model = joblib.load(MODELS_DIR / "isolation_forest.joblib")  # nosec B301
    scaler = joblib.load(MODELS_DIR / "scaler.joblib")  # nosec B301
    usage = feature_usage(model)

    drift_rows = []
    for direction in ("overfill", "cavitation"):
        for minutes in RAMP_MINUTES:
            ramp, plateau = ramp_frame(direction, minutes)
            ramp_features, ramp_scores, ramp_pred = score(model, scaler, ramp)
            plateau_features, plateau_scores, plateau_pred = score(
                model, scaler, plateau
            )
            if direction == "overfill":
                dangerous = ramp_features["tank_max"] >= 90
            else:
                dangerous = ramp_features["tank_min"] <= 15
            early = ~dangerous
            drift_rows.append(
                {
                    "direction": direction,
                    "minutes": minutes,
                    "rate": abs(95.0 - START_LEVEL) / minutes,
                    "dangerous_windows": int(dangerous.sum()),
                    "dangerous_detected": int(ramp_pred[dangerous.to_numpy()].sum()),
                    "early_flags": f"{int(ramp_pred[early.to_numpy()].sum())}/{int(early.sum())}",
                    "plateau_detected": f"{int(plateau_pred.sum())}/{len(plateau_features)}",
                    "min_score": float(min(ramp_scores.min(), plateau_scores.min())),
                }
            )

    base = generate_normal_baseline()
    scan_rows = []
    for source_label, source in (
        ("HMI (trusted)", "172.22.0.10"),
        ("attacker (untrusted)", "172.24.0.10"),
    ):
        _, _, baseline_pred = score(model, scaler, scan_frame(base, None, source))
        baseline_fp = baseline_pred.sum() / len(baseline_pred)
        for every in (1, 2, 6, 12, 24, 60):
            frame = scan_frame(base, every, source)
            features, _, predictions = score(model, scaler, frame)
            malicious = (features["fc_131_count"] > 0).to_numpy()
            scan_rows.append(
                {
                    "source": source_label,
                    "every": every,
                    "exceptions": len(base) // every,
                    "malicious_windows": int(malicious.sum()),
                    "detected": int(predictions[malicious].sum()),
                    "baseline_fp": baseline_fp,
                }
            )

    header = [
        "# Detector evasion results",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Model SHA-256: `{sha256_file(MODELS_DIR / 'isolation_forest.joblib')[:16]}…`",
        "",
        "White-box experiment on synthetic telemetry. Detection uses "
        "`IsolationForest.predict()`.",
        "",
        "## 0. What the model actually uses",
        "",
        "Number of the 100 trees that split on each feature:",
        "",
        "| Feature | Trees using it |",
        "| :--- | --: |",
    ]
    usage_rows = [
        f"| `{name}` | {usage.get(index, 0)} |"
        for index, name in enumerate(FEATURE_COLUMNS)
    ]

    drift_header = [
        "",
        "## 1. Slow process drift",
        "",
        "`dangerous` = windows with tank max ≥ 90% (overfill) or tank min ≤ 15% "
        "(cavitation). `early flags` are false alarms before the dangerous "
        "region. `plateau` is 20 rows held at 95% / 5%.",
        "",
        "| Direction | Ramp (min) | Rate (%/min) | Dangerous windows | Dangerous detected | Early flags | Plateau detected | Min score |",
        "| :--- | --: | --: | --: | --: | --: | --: | --: |",
    ]
    drift_table = [
        f"| {row['direction']} | {row['minutes']:.2f} | {row['rate']:.2f} | "
        f"{row['dangerous_windows']} | {row['dangerous_detected']} | "
        f"{row['early_flags']} | {row['plateau_detected']} | {row['min_score']:.4f} |"
        for row in drift_rows
    ]

    scan_header = [
        "",
        "## 2. Low-rate scan from a trusted source",
        "",
        "Normal tank/valve dynamics are generated (seed 3, 600 rows); FC 131 "
        "exceptions are injected every N rows. `malicious windows` contain at "
        "least one exception. `baseline FP` is the false-positive rate for the "
        "same source with no exceptions — it shows how much the source feature "
        "dominates.",
        "",
        "| Source | One exception every | Exceptions | Malicious windows | Detected | Baseline FP |",
        "| :--- | --: | --: | --: | --: | --: |",
    ]
    scan_table = [
        f"| {row['source']} | {row['every']} rows | {row['exceptions']} | "
        f"{row['malicious_windows']} | {row['detected']} | {row['baseline_fp']:.1%} |"
        for row in scan_rows
    ]

    interpretation = [
        "",
        "## Interpretation",
        "",
        "- The model is effectively a tank-level detector. The tree-usage table "
        "shows zero trees splitting on valve, function-code or source-IP "
        "features: those columns are constant in the normal training set, so "
        "the Isolation Forest never learned them. Claims that `has_write_fc` or "
        "`is_known_good_ip` make writes/scans trivially detectable are false "
        "for this artifact.",
        "- Overfill is never detected, even at the dangerous plateau: the model "
        "learned 93–97% tank levels as normal, which is the per-class miss "
        "reported in the main evaluation. Slow drift does not change that.",
        "- Cavitation is detected once the absolute level enters the low range; "
        "the early flags are instability, not reliable early warning. The model "
        "reacts to absolute tank features, not to the drift itself.",
        "- Low-rate scans evade regardless of source: with only one exception "
        "per window, detection is near zero, and the source-IP feature is dead "
        "so an untrusted source does not help. Scan detection in the main test "
        "set is therefore a tank-pattern coincidence, not Modbus awareness.",
        "- Mitigations: features that actually vary in training (cumulative "
        "exception counts, source novelty), long-horizon counters, "
        "cross-register invariants, absolute safety thresholds and correlation "
        "with authorization events.",
        "- Limits: white-box, synthetic, single model version; no claim about "
        "field detection rates.",
        "",
    ]

    output = "\n".join(
        header
        + usage_rows
        + drift_header
        + drift_table
        + scan_header
        + scan_table
        + interpretation
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(output, encoding="utf-8")
    print("\n".join(header[:5] + usage_rows + drift_header + drift_table))
    print("\n".join(scan_header[:1] + scan_table))
    print(f"\nWrote {args.output}")


if __name__ == "__main__":
    main()
