"""
generate_telemetry.py — Development tool for generating realistic OT telemetry.

Purpose:
    Simulates a Modbus polling loop for the OT-Security-Lab's plc-intake.
    Outputs normal process telemetry with optional anomaly injection for
    training and evaluating the ML anomaly detection model.

Usage:
    python scripts/generate_telemetry.py                            # 30 min normal data
    python scripts/generate_telemetry.py --duration 600             # 10 min
    python scripts/generate_telemetry.py --interactive              # keyboard injection
    python scripts/generate_telemetry.py --schedule schedule.json   # scheduled injection
    python scripts/generate_telemetry.py --seed 123                 # reproducible run

Output:
    data/telemetry.csv    — time-series register snapshots
    data/annotations.csv  — ground truth anomaly labels

Register map:
    Reg 0 — Inlet Valve State (0=CLOSED, 1=OPEN)
    Reg 1 — Reserved (always 0)
    Reg 2 — Reserved (always 0)
    Reg 3 — Reserved (always 0)
    Reg 4 — Reserved (always 0)
    Reg 5 — Tank Level (0-100%)

    Registers 1-4 are kept at 0 to keep feature dimensionality minimal
    for the first model iteration. They exist in the raw Modbus read
    response but have no physical meaning assigned in this lab. Adding
    noise or assigning meaning later is a zero-cost change.
"""

import argparse
import csv
import json
import os
import queue
import random
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class Config:
    poll_interval: float = 5.0
    normal_src_ip: str = "172.22.0.10"
    attacker_ip: str = "172.24.0.10"
    auth_ews_ip: str = "172.23.0.4"
    plc_id: str = "plc_intake"
    plc_ip: str = "172.21.0.10"
    treatment_ip: str = "172.21.0.11"
    distribution_ip: str = "172.21.0.12"
    tank_min: float = 5.0
    tank_max: float = 85.0
    valve_open_threshold: float = 20.0
    valve_close_threshold: float = 80.0
    fill_rate_min: float = 0.3
    fill_rate_max: float = 1.5
    drain_rate_min: float = 0.3
    drain_rate_max: float = 1.5
    normal_fc: int = 3
    write_fc: int = 6
    exception_fc: int = 131
    seed: int = 42
    output_dir: str = "data"

    def __post_init__(self):
        self.all_plc_ips = [self.plc_ip, self.treatment_ip, self.distribution_ip]


FC_NAMES = {
    3: "READ_HOLDING",
    6: "WRITE_SINGLE",
    16: "WRITE_MULTIPLE",
    131: "EXCEPTION",
}

ANOMALY_LABELS = {
    "overfill": 1,
    "cavitation": 2,
    "unauthorized_write": 3,
    "physics_violation": 4,
    "scanning": 5,
}


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

@dataclass
class PlcState:
    tank_level: float = 45.0
    valve_state: int = 0  # 0=CLOSED, 1=OPEN


# ---------------------------------------------------------------------------
# Physics Engine
# ---------------------------------------------------------------------------

class PhysicsEngine:
    """Bounded random walk with valve logic for a single PLC."""

    def __init__(self, config: Config, rng: random.Random):
        self.config = config
        self.rng = rng

    def tick(self, state: PlcState) -> PlcState:
        tank = state.tank_level
        valve = state.valve_state

        if valve == 0:
            step = self.rng.uniform(self.config.fill_rate_min, self.config.fill_rate_max)
            tank += step
            reversion = (self.config.valve_close_threshold - tank) * 0.05
            tank += reversion
        else:
            step = self.rng.uniform(self.config.drain_rate_min, self.config.drain_rate_max)
            tank -= step
            reversion = (self.config.valve_open_threshold - tank) * 0.05
            tank += reversion

        tank = max(self.config.tank_min, min(self.config.tank_max, tank))

        if tank >= self.config.valve_close_threshold:
            valve = 0
        elif tank <= self.config.valve_open_threshold:
            valve = 1

        return PlcState(tank_level=round(tank, 1), valve_state=valve)


# ---------------------------------------------------------------------------
# Anomaly Injectors
# ---------------------------------------------------------------------------

class AnomalyInjector:
    """Applies anomaly effects to telemetry rows."""

    def __init__(self, config: Config, rng: random.Random):
        self.config = config
        self.rng = rng
        self.active: dict = {}

    def set_active(self, anomaly_type: str, active: bool):
        if active:
            self.active[anomaly_type] = time.time()
        else:
            self.active.pop(anomaly_type, None)

    def is_active(self, anomaly_type: str) -> bool:
        return anomaly_type in self.active

    def any_active(self) -> bool:
        return len(self.active) > 0

    def active_types(self) -> list[str]:
        return list(self.active.keys())

    def apply(self, state: PlcState, config_override: dict) -> dict:
        if not self.any_active():
            return config_override

        crow = dict(config_override)

        if self.is_active("overfill"):
            state.tank_level = self.rng.uniform(93, 97)
            state.tank_level = round(state.tank_level, 1)
            crow["function_code"] = self.config.normal_fc
            crow["function_name"] = FC_NAMES[self.config.normal_fc]
            crow["source_ip"] = self.config.normal_src_ip

        if self.is_active("cavitation"):
            state.tank_level = self.rng.uniform(3, 7)
            state.tank_level = round(state.tank_level, 1)
            crow["function_code"] = self.config.normal_fc
            crow["function_name"] = FC_NAMES[self.config.normal_fc]
            crow["source_ip"] = self.config.normal_src_ip

        if self.is_active("unauthorized_write"):
            state.valve_state = 1
            crow["function_code"] = self.config.write_fc
            crow["function_name"] = FC_NAMES[self.config.write_fc]
            crow["source_ip"] = self.config.attacker_ip

        if self.is_active("physics_violation"):
            state.valve_state = 1
            state.tank_level = self.rng.uniform(91, 96)
            state.tank_level = round(state.tank_level, 1)
            crow["function_code"] = self.config.normal_fc
            crow["function_name"] = FC_NAMES[self.config.normal_fc]
            crow["source_ip"] = self.config.attacker_ip

        if self.is_active("scanning"):
            crow["function_code"] = self.config.exception_fc
            crow["function_name"] = FC_NAMES[self.config.exception_fc]
            crow["source_ip"] = self.config.attacker_ip

        return crow


# ---------------------------------------------------------------------------
# CSV Writers
# ---------------------------------------------------------------------------

class DataWriter:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.telemetry_path = self.output_dir / "telemetry.csv"
        self.annotations_path = self.output_dir / "annotations.csv"
        self.telemetry_fh = None
        self.annotations_fh = None
        self.telemetry_writer = None
        self.annotations_writer = None

    def __enter__(self):
        self.telemetry_fh = open(self.telemetry_path, "w", newline="")
        self.annotations_fh = open(self.annotations_path, "w", newline="")

        telemetry_fields = [
            "timestamp", "plc_id", "plc_ip",
            "reg_0_inlet_valve", "reg_1", "reg_2", "reg_3", "reg_4",
            "reg_5_tank_level", "source_ip", "function_code", "function_name",
        ]
        self.telemetry_writer = csv.DictWriter(self.telemetry_fh, fieldnames=telemetry_fields)
        self.telemetry_writer.writeheader()

        annotation_fields = ["start_time", "end_time", "anomaly_type", "description"]
        self.annotations_writer = csv.DictWriter(self.annotations_fh, fieldnames=annotation_fields)
        self.annotations_writer.writeheader()

        return self

    def __exit__(self, *args):
        if self.telemetry_fh:
            self.telemetry_fh.close()
        if self.annotations_fh:
            self.annotations_fh.close()

    def write_telemetry(self, row: dict):
        self.telemetry_writer.writerow(row)
        self.telemetry_fh.flush()

    def write_annotation(self, start: str, end: str, anomaly_type: str, description: str):
        self.annotations_writer.writerow({
            "start_time": start,
            "end_time": end,
            "anomaly_type": anomaly_type,
            "description": description,
        })
        self.annotations_fh.flush()


# ---------------------------------------------------------------------------
# Keyboard Listener (interactive mode)
# ---------------------------------------------------------------------------

class KeyboardListener:
    """Reads stdin in a background thread and puts commands on a queue."""

    HELP_TEXT = """
Keyboard commands (press Enter after each):
  0  — Resume normal operation
  1  — Inject: Overfill (tank > 90%)
  2  — Inject: Cavitation (tank < 10%)
  3  — Inject: Unauthorized Modbus write
  4  — Inject: Physics violation (valve OPEN + tank > 90%)
  5  — Inject: Scanning / brute force
  h  — Show this help
  q  — Quit
"""

    def __init__(self, cmd_queue: queue.Queue):
        self.cmd_queue = cmd_queue
        self.running = True
        self.thread = threading.Thread(target=self._listen, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.running = False

    def _listen(self):
        print(self.HELP_TEXT)
        while self.running:
            try:
                line = sys.stdin.readline().strip().lower()
            except (EOFError, OSError):
                break
            if not line:
                continue
            self.cmd_queue.put(line)
            if line in ("q", "quit"):
                self.running = False
                break


CMD_TO_ANOMALY = {
    "0": None,
    "1": "overfill",
    "2": "cavitation",
    "3": "unauthorized_write",
    "4": "physics_violation",
    "5": "scanning",
}

ANOMALY_DESCRIPTIONS = {
    "overfill": "Tank level exceeded 90% — overfill risk",
    "cavitation": "Tank level dropped below 10% — cavitation risk",
    "unauthorized_write": "Modbus write (FC 6) from untrusted IP",
    "physics_violation": "Valve OPEN while tank level > 90% — impossible state",
    "scanning": "Rapid Modbus exceptions from untrusted IP — scanning detected",
}


# ---------------------------------------------------------------------------
# Schedule Loader
# ---------------------------------------------------------------------------

def load_schedule(path: str) -> list[dict]:
    with open(path) as f:
        data = json.load(f)

    if isinstance(data, list):
        return data

    if isinstance(data, dict) and "schedule" in data:
        return data["schedule"]

    raise ValueError(
        "Schedule must be a JSON array of entries or an object with a 'schedule' key. "
        f"Got: {type(data).__name__}"
    )


# ---------------------------------------------------------------------------
# Row Builder
# ---------------------------------------------------------------------------

def build_row(
    timestamp: str,
    state: PlcState,
    config_override: dict,
    config: Config,
) -> dict:
    return {
        "timestamp": timestamp,
        "plc_id": config.plc_id,
        "plc_ip": config.plc_ip,
        "reg_0_inlet_valve": state.valve_state,
        "reg_1": 0,
        "reg_2": 0,
        "reg_3": 0,
        "reg_4": 0,
        "reg_5_tank_level": state.tank_level,
        "source_ip": config_override.get("source_ip", config.normal_src_ip),
        "function_code": config_override.get("function_code", config.normal_fc),
        "function_name": config_override.get(
            "function_name", FC_NAMES[config.normal_fc]
        ),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate realistic OT telemetry for ML model training."
    )
    parser.add_argument(
        "--duration", type=int, default=1800,
        help="Run duration in seconds (default: 1800 = 30 min)",
    )
    parser.add_argument(
        "--interactive", action="store_true",
        help="Enable keyboard-based anomaly injection",
    )
    parser.add_argument(
        "--schedule", type=str, default=None,
        help="JSON schedule file for automated anomaly injection",
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    parser.add_argument(
        "--output", type=str, default="data",
        help="Output directory (default: data/)",
    )
    parser.add_argument(
        "--fast", action="store_true",
        help="Generate data as fast as possible (skip real-time sleep)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    config = Config(seed=args.seed, output_dir=args.output)
    rng = random.Random(config.seed)

    physics = PhysicsEngine(config, rng)
    injector = AnomalyInjector(config, rng)

    cmd_queue: queue.Queue = queue.Queue()

    interactive_mode = args.interactive
    keyboard = None
    if interactive_mode:
        keyboard = KeyboardListener(cmd_queue)
        keyboard.start()

    schedule = None
    schedule_entries = []
    schedule_stop_times: dict[str, float] = {}
    if args.schedule:
        schedule_entries = load_schedule(args.schedule)
        schedule_entries.sort(key=lambda e: e["time"])
        schedule = list(schedule_entries)

    state = PlcState()

    total_ticks = int(args.duration / config.poll_interval)
    start_time_dt = datetime.now(timezone.utc).replace(microsecond=0)

    def tick_timestamp(tick_index: int) -> str:
        dt = start_time_dt.replace(microsecond=0)
        offset = int(tick_index * config.poll_interval)
        dt = datetime.fromtimestamp(dt.timestamp() + offset, tz=timezone.utc)
        return dt.isoformat()

    anomaly_start_times: dict[str, str] = {}

    print(f"Generating {total_ticks} rows ({args.duration}s at {config.poll_interval}s intervals)...")
    print(f"Output dir: {config.output_dir}/")
    print(f"Interactive: {interactive_mode}  |  Schedule: {bool(schedule)}")

    if interactive_mode:
        print("Keyboard mode active. Press 'h' for commands.")

    with DataWriter(config.output_dir) as writer:
        for tick in range(total_ticks):
            elapsed = tick * config.poll_interval
            tick_dt = tick_timestamp(tick)

            # --- Process keyboard commands ---
            if interactive_mode:
                while not cmd_queue.empty():
                    cmd = cmd_queue.get_nowait()
                    if cmd in ("q", "quit"):
                        print("Quit requested.")
                        return
                    if cmd == "h":
                        print(KeyboardListener.HELP_TEXT)
                        continue
                    anomaly_type = CMD_TO_ANOMALY.get(cmd)
                    if anomaly_type is None:
                        print(f"Unknown command: {cmd}. Press 'h' for help.")
                        continue
                    if anomaly_type is None:
                        for at in list(injector.active.keys()):
                            if at not in CMDS:
                                injector.set_active(at, False)
                    else:
                        toggling_on = not injector.is_active(anomaly_type)
                        injector.set_active(anomaly_type, toggling_on)
                        label = "ON" if toggling_on else "OFF"
                        print(f"  [{label}] {ANOMALY_DESCRIPTIONS.get(anomaly_type, anomaly_type)}")

            # Normal resets: "0" handler already covered above — toggle off all
            if not cmd_queue.empty():
                pass  # already processed

            # --- Process schedule ---
            if schedule and schedule_entries:
                while schedule_entries and elapsed >= schedule_entries[0]["time"]:
                    entry = schedule_entries.pop(0)
                    atype = entry["type"]
                    injector.set_active(atype, True)
                    duration = entry.get("duration", 10)
                    schedule_stop_times[atype] = elapsed + duration
                    print(f"  [SCHEDULE] {ANOMALY_DESCRIPTIONS.get(atype, atype)} (duration={duration}s)")
                    anomaly_start_times.setdefault(atype, tick_dt)

            # Auto-stop scheduled anomalies when duration expires
            for atype in list(schedule_stop_times.keys()):
                if elapsed >= schedule_stop_times[atype]:
                    injector.set_active(atype, False)
                    del schedule_stop_times[atype]

            # --- Physics step ---
            state = physics.tick(state)

            # --- Anomaly override ---
            config_override: dict = {}
            config_override = injector.apply(state, config_override)

            # Handle scanning: cycle through PLC IPs
            if injector.is_active("scanning"):
                cycle_index = tick % 3
                cic = [config.plc_ip, config.treatment_ip, config.distribution_ip]
                config_override["plc_ip"] = cic[cycle_index]
                config_override["plc_id"] = f"plc_{['intake', 'treatment', 'distribution'][cycle_index]}"
            else:
                config_override["plc_ip"] = config.plc_ip
                config_override["plc_id"] = config.plc_id

            # --- Write telemetry row ---
            row = build_row(tick_dt, state, config_override, config)
            row["plc_ip"] = config_override.get("plc_ip", config.plc_ip)
            row["plc_id"] = config_override.get("plc_id", config.plc_id)
            writer.write_telemetry(row)

            # --- Annotation tracking ---
            for atype in injector.active_types():
                if atype not in anomaly_start_times:
                    anomaly_start_times[atype] = tick_dt

            ended_types = []
            for atype, a_start in anomaly_start_times.items():
                if not injector.is_active(atype):
                    writer.write_annotation(
                        start=a_start,
                        end=tick_dt,
                        anomaly_type=atype,
                        description=ANOMALY_DESCRIPTIONS.get(atype, atype),
                    )
                    ended_types.append(atype)

            for atype in ended_types:
                anomaly_start_times.pop(atype, None)

            # --- Wait (skip in --fast mode) ---
            if not args.fast:
                time.sleep(config.poll_interval)

        # --- Flush remaining annotations at end of run ---
        end_ts = tick_timestamp(total_ticks - 1) if total_ticks > 0 else datetime.now(timezone.utc).isoformat()
        for atype, a_start in anomaly_start_times.items():
            writer.write_annotation(
                start=a_start,
                end=end_ts,
                anomaly_type=atype,
                description=ANOMALY_DESCRIPTIONS.get(atype, atype),
            )

    print(f"\nDone. {total_ticks} rows written.")
    print(f"  Telemetry:  {writer.telemetry_path}")
    print(f"  Annotations: {writer.annotations_path}")


if __name__ == "__main__":
    main()
