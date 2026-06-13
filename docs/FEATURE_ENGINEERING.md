# Feature Engineering — Anomaly Detection Pipeline

## 1. Windowing Strategy

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Polling interval | 5 seconds | Matches lab's Grafana refresh rate |
| Window size | 6 rows (30 seconds) | Long enough to observe a multi-step attack sequence (probe → write → spoofed read), short enough for near-real-time detection |
| Stride | 1 row (overlapping) | Each window is 30s of context; sliding by 5s gives 5× more training windows than non-overlapping, which is critical given the limited pure-normal prefix available |
| Training data | `data/train/telemetry.csv` — 15 minutes of pure normal operation (no anomalies, no schedule) |
| Test data | `data/test/telemetry.csv` — 20 minutes with 5 injected anomaly windows starting at 600s |
| Train/test split | Trained on the dedicated normal-only dataset; tested on the full anomaly dataset. No temporal leakage because training contains zero anomaly rows. |

## 2. Features

All features are computed per window (6 rows). The raw CSV columns map to the following engineered features:

### Tank Level (reg_5) — 6 features

| Feature | Derivation | Purpose |
|---------|------------|---------|
| `tank_mean` | Mean of 6 reg_5 values | Central tendency of the water level |
| `tank_std` | Standard deviation | Spread — anomalies often cause abrupt jumps or erratic readings |
| `tank_min` | Minimum | Captures low outliers (cavitation) |
| `tank_max` | Maximum | Captures high outliers (overfill) |
| `tank_last` | Last (most recent) value | Current state — most actionable for real-time response |
| `tank_roc` | `tank_last - tank_first` | Rate of change over the 30s window. Normal: ±2% per minute = ±1% per window. Anomalies: ±15%+ |

### Inlet Valve (reg_0) — 4 features

| Feature | Derivation | Purpose |
|---------|------------|---------|
| `valve_mean` | Mean of 6 reg_0 values | 0.0 = always closed, 1.0 = always open, 0.5 = toggled |
| `valve_std` | Standard deviation | > 0 indicates a state change within the window |
| `valve_last` | Last valve state | Current position |
| `valve_changed` | Binary: 1 if any reg_0 value differs from the first | Flags valve toggling within the 30s window — unusual in steady-state operation |

### Function Codes — 3 features

The raw function_code column is one-hot encoded via counts per window. A normal window has 6 READ_HOLDING (FC 3) and 0 of everything else.

| Feature | Derivation | Normal Value |
|---------|------------|-------------|
| `fc_3_count` | Count of FC 3 rows in the window | 6 |
| `fc_6_count` | Count of FC 6 (WRITE_SINGLE) rows | 0 |
| `fc_131_count` | Count of FC 131 (EXCEPTION) rows | 0 |

FC 16 (WRITE_MULTIPLE) is not present in the generated data but would follow the same pattern.

### Source IP — 1 feature

| Feature | Derivation | Normal Value |
|---------|------------|-------------|
| `is_known_good_ip` | 1 if all 6 rows have source_ip in `{172.22.0.10, 172.23.0.4}`, else 0 | 1 |

This is preferred over one-hot encoding individual IPs because:
- The allowlist is small and known
- Any novel IP (e.g., attacker `172.24.0.10`) immediately produces a 0
- It avoids feature explosion from unseen IPs

### Unnamed Registers (reg_1–reg_4)

**Excluded.** In the generated telemetry, reg_1 through reg_4 are always 0 across all 420 rows (180 train + 240 test). Including constant features adds no signal, increases dimensionality, and can degrade Isolation Forest split quality. If these registers are later assigned physical meanings and their values begin varying, they should be re-added with the same aggregation functions as reg_5.

### Total Feature Vector

| Group | Count |
|-------|-------|
| Tank level (reg_5) | 6 |
| Valve (reg_0) | 4 |
| Function codes | 3 |
| Source IP | 1 |
| **Numerical features** | **14** |
| + timestamp (for plotting, not a feature) | 1 |

## 3. Scaling

**StandardScaler** (z-score: subtract mean, divide by standard deviation).

Rationale:
- Isolation Forest splits feature space with distance-based criteria. A feature with range 0–100 (tank level) would dominate a feature with range 0–1 (valve state) by 100× without scaling.
- StandardScaler is appropriate because training data contains only normal operation — there are no outliers to skew the mean/variance estimates.
- Fit on training data only; transform both train and test using the training fit to avoid data leakage.

## 4. Expected Output Shapes

| Dataset | Raw rows | Windows (win=6, stride=1) | Feature matrix |
|---------|----------|---------------------------|----------------|
| Train | 180 | 180 - 6 + 1 = **175** | 175 × 14 |
| Test | 240 | 240 - 6 + 1 = **235** | 235 × 14 |

## 5. Feature Pipeline (Pseudocode)

```
def build_windows(df, window_size=6, stride=1):
    windows = []
    timestamps = []
    for i in range(0, len(df) - window_size + 1, stride):
        w = df.iloc[i:i+window_size]
        windows.append({
            "tank_mean": w["reg_5_tank_level"].mean(),
            "tank_std":  w["reg_5_tank_level"].std(),
            "tank_min":  w["reg_5_tank_level"].min(),
            "tank_max":  w["reg_5_tank_level"].max(),
            "tank_last": w["reg_5_tank_level"].iloc[-1],
            "tank_roc":  w["reg_5_tank_level"].iloc[-1] - w["reg_5_tank_level"].iloc[0],
            "valve_mean": w["reg_0_inlet_valve"].mean(),
            "valve_std":  w["reg_0_inlet_valve"].std(),
            "valve_last": w["reg_0_inlet_valve"].iloc[-1],
            "valve_changed": 1 if w["reg_0_inlet_valve"].nunique() > 1 else 0,
            "fc_3_count":   (w["function_code"] == 3).sum(),
            "fc_6_count":   (w["function_code"] == 6).sum(),
            "fc_131_count": (w["function_code"] == 131).sum(),
            "is_known_good_ip": 1 if w["source_ip"].isin(["172.22.0.10", "172.23.0.4"]).all() else 0,
        })
        timestamps.append(w["timestamp"].iloc[-1])
    return pd.DataFrame(windows), timestamps
```
