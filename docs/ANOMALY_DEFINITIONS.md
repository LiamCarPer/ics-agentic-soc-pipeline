# Anomaly Definitions — Agentic OT SOC Analyst

This document defines what "normal" looks like in my OT-Security-Lab, what constitutes an anomaly, and how each anomaly maps to measurable features. These definitions directly drive feature engineering, model training, and evaluation.

---

## 1. Normal Operating Envelope

### Monitored Asset

| Asset | IP Address | Device Type | Firmware |
|-------|------------|-------------|----------|
| plc-intake | 172.21.0.10 | OpenPLC v4 | 4.0.7 |

### Register Map

| Register | Parameter | Normal Range | Rate Limit | Control Logic |
|----------|-----------|--------------|------------|---------------|
| Reg 0 | Inlet Valve State | 0 (CLOSED) or 1 (OPEN) | N/A (instantaneous) | Valve OPEN when tank level < 20%. Valve CLOSED when tank level > 80%. |
| Reg 1 | Unused | 0 | N/A | Always 0 in normal operation. |
| Reg 2 | Unused | 0 | N/A | Always 0 in normal operation. |
| Reg 3 | Unused | 0 | N/A | Always 0 in normal operation. |
| Reg 4 | Unused | 0 | N/A | Always 0 in normal operation. |
| Reg 5 | Tank Level | 20–80% | ±2% per minute | Drains toward 20% when valve OPEN. Fills toward 80% when valve CLOSED. |

### Normal Traffic Pattern

| Property | Normal Value |
|----------|-------------|
| Polling interval | 5 seconds |
| Function codes observed | FC 3 (Read Holding Registers) |
| Source IPs | `172.22.0.10` (ot-hmi) — authorized SCADA reads |
| Write sources | `172.23.0.4` (eng-ws-01) — authorized engineering workstation only |
| Transaction rate | 1 read per 5 seconds = 12 reads/minute per PLC |
| Register count per read | 6 registers (addresses 0–5) |

### Normal Behavior Over a Typical Cycle

1. Tank level is at 20–80%. Valve is CLOSED if level > 80%, OPEN if level < 20%.
2. HMI polls plc-intake every 5 seconds via Modbus FC 3.
3. Tank level rises ~1–2% per read when valve is CLOSED (filling).
4. Tank level drops ~1–2% per read when valve is OPEN (draining).
5. Valve state changes are infrequent and triggered only by crossing the 20%/80% thresholds.
6. No Modbus writes (FC 6/16) occur during normal operation unless an operator is actively commanding a valve change from the engineering workstation.

---

## 2. Anomaly Scenarios

### Scenario A: Process Anomaly — Tank Level Out of Bounds

**Description:** Tank level exceeds 90% (overfill risk) or drops below 10% (cavitation risk) without a corresponding valve state change.

**MITRE Reference:** T0836 (Modify Parameter)

**Detection logic:**
- `reg_5_tank_level > 90` OR `reg_5_tank_level < 10`
- AND no authorized valve command was issued in the preceding 30 seconds (no FC 6 from `172.23.0.4`)
- OR valve state contradicts the level (e.g., valve OPEN at 95% — physics violation)

**Feature vector signature:**
```
tank_level_mean_last_3_reads: > 90
valve_state: OPEN (1)  ← contradicts safe operation
source_ip: 172.22.0.10 (HMI) or 172.24.0.10 (attacker)
function_code: 3 (read — HMI saw the spoofed value)
rate_of_change_last_60s: > +10%  ← exceeds normal ±2%/min limit
```

**Severity:** Critical — immediate physical risk to the water treatment process.

### Scenario B: Unauthorized Command — Modbus Write from Untrusted IP

**Description:** A Modbus write (FC 6) or write multiple (FC 16) command from any IP other than the authorized engineering workstation (`172.23.0.4`).

**MITRE Reference:** T0831 (Manipulation of Control)

**Detection logic:**
- `function_code == 6` OR `function_code == 16`
- AND `source_ip` is NOT `172.23.0.4`

**Feature vector signature:**
```
function_code: 6
source_ip: 172.24.0.10 (attacker)
target_register: 0 (inlet valve)
written_value: 1 (OPEN)
authorized_source: False
```

**Variant — write from HMI:** If the detection rule is strict (only eng-ws-01 should write), then writes from the HMI IP (`172.22.0.10`) also trigger this alert. In a real deployment the HMI could be a legitimate write source depending on the control architecture.

**Severity:** High — indicates active network intrusion and potential loss of control.

### Scenario C: Physics Violation — Impossible State Combination

**Description:** The valve is OPEN while tank level > 90%, or the valve is CLOSED while tank level is dropping (suggesting a leak or sensor manipulation). This detection requires cross-register coherence checking.

**MITRE Reference:** T0836 (Modify Parameter)

**Detection logic:**
- `reg_0_inlet_valve == 1` AND `reg_5_tank_level > 90` — valve open during tank > 90% is a safety interlock violation
- OR `reg_0_inlet_valve == 0` AND `reg_5_tank_level` is decreasing by > 2% per reading for 3+ consecutive reads (potential leak or sensor tampering)

**Feature vector signature:**
```
valve_state: OPEN (1)
tank_level: 95%
physics_violation_score: 1.0  (binary — combination is impossible under normal control logic)
rate_of_change_last_3_reads: +15% (abnormal rise despite valve being OPEN)
```

**Severity:** Critical — indicates either sensor spoofing (attacker injecting false telemetry) or a control logic bypass.

### Scenario D: Scanning / Reconnaissance — Rapid Reads from Untrusted IP

**Description:** Rapid Modbus read requests from an IP not in the asset inventory, targeting multiple registers or multiple PLCs in quick succession.

**MITRE Reference:** T0846 (Brute Force / Scanning)

**Detection logic:**
- More than 5 Modbus exception responses (FC 131) from a single source IP within a 60-second sliding window
- OR read requests from a single new IP to 3+ distinct PLC IPs within 30 seconds
- OR read requests spanning 10+ different register addresses within a single burst

**Feature vector signature:**
```
source_ip: 172.24.0.10
request_rate_last_60s: 12 reads (normal is 0 from this IP)
exception_count_last_60s: 7
unique_plcs_contacted_last_30s: 3 (intake, treatment, distribution)
register_span_last_burst: 6 (0–5)
authorized_source: False
```

**Severity:** Medium — pre-attack reconnaissance. Escalates to High if followed by a write attempt.

---

## 3. Labels and Expected Data Signatures

| Label | Numeric Encoded | Windowed Features | Alert Trigger |
|-------|----------------|-------------------|---------------|
| `normal` | 0 | `tank_level in [20,80]`, `fc==3`, `src in [172.22.0.10]`, `roc < 2%/min` | None |
| `overfill_risk` | 1 | `tank_level > 90`, `valve_state==0 or 1`, `roc > +2%/min` | `reg_5_tank_level > 90` for any 2 of 3 consecutive reads |
| `cavitation_risk` | 2 | `tank_level < 10`, `valve_state==0 or 1`, `roc < -2%/min` | `reg_5_tank_level < 10` for any 2 of 3 consecutive reads |
| `unauthorized_write` | 3 | `fc==6 or 16`, `src not in [172.23.0.4]`, `reg in [0..5]` | Single FC 6/16 packet from non-authorized IP |
| `physics_violation` | 4 | `valve==1 and tank>90` OR `valve==0 and tank dropping for 3 reads` | Cross-register coherence check fails |
| `scanning` | 5 | `src not in [172.22.0.10, 172.23.0.4]`, `exception_count > 5 in 60s`, `unique_plcs >= 3 in 30s` | Sliding window threshold exceeded |

### Feature Engineering Notes

| Feature | Derivation |
|---------|-----------|
| `tank_level_mean_last_N` | Rolling mean of `reg_5` over last N windows |
| `tank_level_roc` | (current_tank_level - previous_tank_level) / interval_seconds |
| `valve_state` | Direct from `reg_0` — no smoothing needed (binary) |
| `physics_violation_score` | 1 if `valve==1 AND tank_level > 90`, else 0 |
| `function_code` | Direct from Modbus packet byte 7 |
| `authorized_source` | 1 if `source_ip` in authorized list, else 0 |
| `exception_rate` | Count of FC 131 packets per source IP per sliding window |
| `unique_plcs_contacted` | Count of distinct destination IPs (172.21.0.10/11/12) per source IP per time window |
| `write_to_new_ip` | 1 if first observed FC 6/16 from a given source IP |

---

## 4. Edge Cases

### 4.1 Transient Spikes vs. Sustained Anomaly

A single register read showing `tank_level = 95%` could be a network glitch or a transient sensor error. To reduce false positives:

| Anomaly Type | Hold Time | Confirm Reads |
|-------------|-----------|---------------|
| Overfill / Cavitation | 2 of the last 3 consecutive reads must exceed threshold | 3-window median > 90 |
| Physics violation | Instant — impossible state on a single read is enough (if both regs are validated) | Cross-check both registers from the same packet |
| Unauthorized write | Instant — single packet is sufficient (IP spoofing is unlikely in a local lab) | None |
| Scanning | 5+ exceptions in 60s (already a sliding window) | Window-based, not instant |

### 4.2 Network Jitter and Out-of-Order Packets

- **Problem:** Packets may arrive at the sniffer out of order, causing negative rate-of-change values even during normal filling.
- **Mitigation:** Sort telemetry by `timestamp` before computing rate-of-change features. Use the packet timestamp, not the system clock arrival time.
- **Consequence:** If timestamps are missing, use arrival order but flag the window as "suspect" in the feature vector.

### 4.3 Missing Data / Gaps

- **Problem:** If the telemetry collector crashes or the network drops packets, there may be gaps of 10+ seconds between windows.
- **Mitigation:** Rate-of-change features should normalize by actual elapsed time. A 40-second gap followed by a 5% level rise = ~7.5%/min — outside normal bounds.
- **Behavior:** Do not infer values during gaps. Mark gap windows as missing and skip inference for that window.

### 4.4 Simultaneous Attacks

- **Problem:** An attacker might read registers (FC 3) while also sending a malicious write (FC 6). The same window could contain both normal and anomalous traffic.
- **Mitigation:** Feature extraction is per-packet, not per-window. A window containing any packet flagged as anomalous is labeled as anomalous. Multiple anomalies in a single window produce a composite label.

### 4.5 PLC Reboot or Reset

- **Problem:** On boot, PLC registers reset to 0. This produces `tank_level = 0`, `valve = 0` — which looks like cavitation risk and physics violation simultaneously.
- **Mitigation:** Gate anomaly detection on the `function_code` — only flag anomalies on packets where the PLC is responding (FC 3 response, not a request). Monitor for a broadcast of all-zero registers across all 3 PLCs to detect a lab-wide reset vs. a targeted attack.

### 4.6 Stale or Frozen Telemetry

- **Problem:** If the attacker Man-in-the-Middles the HMI-PLC connection and replays old telemetry, the ML model sees a "normal" pattern that is actually stale.
- **Mitigation:** Track the `timestamp` delta between consecutive reads. If the delta is suspiciously consistent (exactly 5.000 seconds every time with no variance) while real traffic has jitter, flag as potential replay.

---

## 5. Summary: Anomaly-to-MITRE Mapping

| Anomaly | MITRE ATT&CK for ICS | Detection Rule Source |
|---------|----------------------|-----------------------|
| Overfill / Cavitation | T0836 (Modify Parameter) | New — ML model from process telemetry |
| Unauthorized Write | T0831 (Manipulation of Control) | Existing `modbus_anomaly.py` + ML enhancement |
| Physics Violation | T0836 (Modify Parameter) | Existing `process_safety_violation.py` + ML enhancement |
| Scanning / Recon | T0846 (Brute Force / Scanning) | Existing `ot_brute_force.py` + ML enhancement |
| Cross-Zone Traffic | T0886 (Remote Services / Lateral Movement) | Existing `cross_zone_traffic.py` (rule-based, kept as separate signal) |

The ML model will focus on anomalies that benefit from statistical detection (overfill, physics violations, subtle drift). The existing rule-based detections will remain as hard triggers and serve as ground truth labels for model evaluation.
