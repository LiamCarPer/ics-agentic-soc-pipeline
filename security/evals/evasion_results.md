# Detector evasion results

Generated: 2026-10-19T18:07:13.100373+00:00
Model SHA-256: `c5503b79d39aa1b9…`

White-box experiment on synthetic telemetry. Detection uses `IsolationForest.predict()`.

## 0. What the model actually uses

Number of the 100 trees that split on each feature:

| Feature | Trees using it |
| :--- | --: |
| `tank_mean` | 99 |
| `tank_std` | 100 |
| `tank_min` | 99 |
| `tank_max` | 99 |
| `tank_last` | 99 |
| `tank_roc` | 100 |
| `valve_mean` | 0 |
| `valve_std` | 0 |
| `valve_last` | 0 |
| `valve_changed` | 0 |
| `fc_3_count` | 0 |
| `fc_6_count` | 0 |
| `fc_131_count` | 0 |
| `has_write_fc` | 0 |
| `is_known_good_ip` | 0 |

## 1. Slow process drift

`dangerous` = windows with tank max ≥ 90% (overfill) or tank min ≤ 15% (cavitation). `early flags` are false alarms before the dangerous region. `plateau` is 20 rows held at 95% / 5%.

| Direction | Ramp (min) | Rate (%/min) | Dangerous windows | Dangerous detected | Early flags | Plateau detected | Min score |
| :--- | --: | --: | --: | --: | --: | --: | --: |
| overfill | 45.00 | 1.00 | 60 | 0 | 150/475 | 0/15 | -0.0470 |
| overfill | 22.50 | 2.00 | 30 | 0 | 171/235 | 0/15 | -0.0684 |
| overfill | 11.25 | 4.00 | 15 | 0 | 49/115 | 0/15 | -0.0662 |
| overfill | 4.50 | 10.00 | 6 | 0 | 13/43 | 0/15 | -0.0545 |
| overfill | 2.25 | 20.00 | 3 | 0 | 2/19 | 0/15 | -0.0365 |
| overfill | 0.75 | 60.00 | 1 | 0 | 1/3 | 0/15 | -0.0027 |
| cavitation | 45.00 | 1.00 | 120 | 120 | 415/415 | 15/15 | -0.0309 |
| cavitation | 22.50 | 2.00 | 60 | 60 | 205/205 | 15/15 | -0.0520 |
| cavitation | 11.25 | 4.00 | 30 | 30 | 100/100 | 15/15 | -0.0520 |
| cavitation | 4.50 | 10.00 | 12 | 12 | 37/37 | 15/15 | -0.0599 |
| cavitation | 2.25 | 20.00 | 6 | 6 | 16/16 | 15/15 | -0.0652 |
| cavitation | 0.75 | 60.00 | 2 | 2 | 2/2 | 15/15 | -0.0718 |

## 2. Low-rate scan from a trusted source

Normal tank/valve dynamics are generated (seed 3, 600 rows); FC 131 exceptions are injected every N rows. `malicious windows` contain at least one exception. `baseline FP` is the false-positive rate for the same source with no exceptions — it shows how much the source feature dominates.

| Source | One exception every | Exceptions | Malicious windows | Detected | Baseline FP |
| :--- | --: | --: | --: | --: | --: |
| HMI (trusted) | 1 rows | 600 | 595 | 2 | 0.3% |
| HMI (trusted) | 2 rows | 300 | 595 | 2 | 0.3% |
| HMI (trusted) | 6 rows | 100 | 595 | 2 | 0.3% |
| HMI (trusted) | 12 rows | 50 | 295 | 1 | 0.3% |
| HMI (trusted) | 24 rows | 25 | 145 | 1 | 0.3% |
| HMI (trusted) | 60 rows | 10 | 55 | 1 | 0.3% |
| attacker (untrusted) | 1 rows | 600 | 595 | 2 | 0.3% |
| attacker (untrusted) | 2 rows | 300 | 595 | 2 | 0.3% |
| attacker (untrusted) | 6 rows | 100 | 595 | 2 | 0.3% |
| attacker (untrusted) | 12 rows | 50 | 295 | 1 | 0.3% |
| attacker (untrusted) | 24 rows | 25 | 145 | 1 | 0.3% |
| attacker (untrusted) | 60 rows | 10 | 55 | 1 | 0.3% |

## Interpretation

- The model is effectively a tank-level detector. The tree-usage table shows zero trees splitting on valve, function-code or source-IP features: those columns are constant in the normal training set, so the Isolation Forest never learned them. Claims that `has_write_fc` or `is_known_good_ip` make writes/scans trivially detectable are false for this artifact.
- Overfill is never detected, even at the dangerous plateau: the model learned 93–97% tank levels as normal, which is the per-class miss reported in the main evaluation. Slow drift does not change that.
- Cavitation is detected once the absolute level enters the low range; the early flags are instability, not reliable early warning. The model reacts to absolute tank features, not to the drift itself.
- Low-rate scans evade regardless of source: with only one exception per window, detection is near zero, and the source-IP feature is dead so an untrusted source does not help. Scan detection in the main test set is therefore a tank-pattern coincidence, not Modbus awareness.
- Mitigations: features that actually vary in training (cumulative exception counts, source novelty), long-horizon counters, cross-register invariants, absolute safety thresholds and correlation with authorization events.
- Limits: white-box, synthetic, single model version; no claim about field detection rates.
