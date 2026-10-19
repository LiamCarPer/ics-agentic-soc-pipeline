# ML security evaluations

Two reproducible experiments measure the detector's security properties beyond
the standard precision/recall table. Both use the committed model and write a
Markdown report next to the script.

## Evasion — `evasion_experiment.py`

```bash
./venv/bin/python security/evals/evasion_experiment.py
```

Measures:

- which features the committed trees actually split on,
- detection of slow overfill/cavitation ramps (dangerous region vs early false
  alarms vs final plateau),
- low-rate Modbus exception scans from a trusted HMI and an untrusted host,
  using generated normal process dynamics.

Result: [`evasion_results.md`](evasion_results.md).

Headline findings: the model is a tank-level detector (0/100 trees use any
valve, function-code or source-IP feature); overfill is never detected; a
low-rate scan is detected in 1–2 of 55–595 malicious windows regardless of
source.

## Poisoning — `poisoning_experiment.py`

```bash
./venv/bin/python security/evals/poisoning_experiment.py
```

Generates five separate corpora with `scripts/generate_telemetry.py` (seeds
7/11/13/17/19), adds cavitation and scanning windows to the normal training set
at 1/5/10/20%, retrains the scaler and Isolation Forest with the committed
hyperparameters, and evaluates on the clean `data/test` set. Each rate is
averaged over 10 random draws.

Result: [`poisoning_results.md`](poisoning_results.md).

Headline findings: 5% poison drops overall recall from 0.650 to 0.215
(scanning 32%, cavitation 62%, physics 5%); 10% drops recall to 0.130
(scanning 6%, cavitation 42%).

## Notes

- These are white-box, synthetic experiments. They quantify limitations and
  motivate defence in depth; they are not field measurements.
- Scripts never overwrite `models/*.joblib`; they train temporary models for the
  poisoning sweep.
- Both scripts verify the committed model manifest before loading.
