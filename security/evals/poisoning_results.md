# Training-data poisoning results

Generated: 2026-10-19T18:03:53.600074+00:00
Committed model SHA-256: `c5503b79d39aa1b9…`

Poison pool: 45 cavitation/scanning windows from 5 separately generated corpora (seeds 7, 11, 13, 17, 19). Each rate is averaged over 10 random draws. Scaler and Isolation Forest are retrained on normal + poison; evaluation is on the clean `data/test` set (20 anomaly windows).

| Poison rate | Added windows | Precision | Recall | F1 | Cavitation | Scanning | Physics | Overfill | Write |
| --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| 0% | 0 | 0.188 | 0.650 | 0.292 | 100% | 100% | 100% | 0% | 0% |
| 1% | 2 | 0.203 | 0.645 | 0.309 | 82% | 100% | 95% | 0% | 27% |
| 5% | 9 | 0.540 | 0.215 | 0.289 | 62% | 32% | 5% | 0% | 0% |
| 10% | 18 | 0.498 | 0.130 | 0.200 | 42% | 6% | 15% | 0% | 0% |
| 20% | 35 | 0.174 | 0.135 | 0.131 | 20% | 0% | 48% | 0% | 0% |

## Interpretation

- Adding anomaly-shaped windows to the normal class teaches the model that those states are benign. Per-class recall for the poisoned classes falls as the poison fraction rises.
- Overfill and unauthorized writes are already missed by the baseline, so poisoning cannot reduce their recall further — a class the model never learned is not protected by anomaly detection.
- Defence: provenance and review of training telemetry, labelled holdouts, drift monitoring, and physics invariants that do not depend on training data.
- Limits: the attacker is assumed to influence the training set; the poison is drawn from the same simulator; the averages reduce but do not eliminate threshold noise from a small dataset.
