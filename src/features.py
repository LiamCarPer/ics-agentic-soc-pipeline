import pandas as pd
from typing import Dict, List, Tuple

FEATURE_COLUMNS: List[str] = [
    "tank_mean",
    "tank_std",
    "tank_min",
    "tank_max",
    "tank_last",
    "tank_roc",
    "valve_mean",
    "valve_std",
    "valve_last",
    "valve_changed",
    "fc_3_count",
    "fc_6_count",
    "fc_131_count",
    "has_write_fc",
    "is_known_good_ip",
]

DEFAULT_WINDOW_SIZE: int = 6
KNOWN_GOOD_IPS: List[str] = ["172.22.0.10", "172.23.0.4"]
WRITE_FUNCTIONS: List[int] = [6, 16]


def engineer_features(window_df: pd.DataFrame) -> Dict[str, float]:
    tank = window_df["reg_5_tank_level"].astype(float)
    valve = window_df["reg_0_inlet_valve"].astype(float)
    fc = window_df["function_code"]
    src = window_df["source_ip"]

    return {
        "tank_mean": tank.mean(),
        "tank_std": tank.std(),
        "tank_min": tank.min(),
        "tank_max": tank.max(),
        "tank_last": tank.iloc[-1],
        "tank_roc": tank.iloc[-1] - tank.iloc[0],
        "valve_mean": valve.mean(),
        "valve_std": valve.std(),
        "valve_last": valve.iloc[-1],
        "valve_changed": 1 if valve.nunique() > 1 else 0,
        "fc_3_count": (fc == 3).sum(),
        "fc_6_count": (fc == 6).sum(),
        "fc_131_count": (fc == 131).sum(),
        "has_write_fc": 1 if fc.isin(WRITE_FUNCTIONS).any() else 0,
        "is_known_good_ip": 1 if src.isin(KNOWN_GOOD_IPS).all() else 0,
    }


def build_windowed_features(
    df: pd.DataFrame,
    window_size: int = DEFAULT_WINDOW_SIZE,
    stride: int = 1,
) -> Tuple[pd.DataFrame, pd.Series]:
    if len(df) < window_size:
        raise ValueError(
            f"DataFrame has {len(df)} rows, but window_size={window_size} "
            f"requires at least {window_size} rows"
        )

    windows = []
    timestamps = []

    for i in range(0, len(df) - window_size + 1, stride):
        w = df.iloc[i : i + window_size]
        windows.append(engineer_features(w))
        timestamps.append(w["timestamp"].iloc[-1])

    result = pd.DataFrame(windows, columns=FEATURE_COLUMNS)
    ts = pd.Series(timestamps, name="timestamp")
    return result, ts
