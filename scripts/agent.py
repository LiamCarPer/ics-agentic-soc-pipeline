"""
agent.py — OT SOC Analyst Level 1 Agent.

Loads an anomaly alert, enriches it via RAG, and uses an LLM agent
(GPT-4o-mini) to analyze the anomaly, draft a NIST incident report,
and generate a Suricata rule.

Usage:
    echo '<alert-json>' | python scripts/agent.py
    python scripts/agent.py --alert <path-to-alert.json>

Environment variables:
    OPENAI_API_KEY      Required. Your OpenAI or OpenRouter API key.
    OPENAI_BASE_URL     Optional. Defaults to OpenAI; set to
                        https://openrouter.ai/api/v1 for OpenRouter.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

_proj_root = Path(__file__).resolve().parent.parent
if str(_proj_root) not in sys.path:
    sys.path.insert(0, str(_proj_root))

from langchain_core.tools import tool
from langchain.agents import create_agent
from langchain_openai import ChatOpenAI

from src.rag import retrieve_context

OUTPUTS_DIR = _proj_root / "outputs"

SYSTEM_PROMPT = """You are a Level 1 SOC Analyst specializing in OT/ICS security at a water treatment facility. You have been given an anomaly alert and contextual knowledge from a RAG pipeline (asset inventory, IEC 62443 controls, past incidents).

You must call tools in this exact sequence:
1. analyze_anomaly — to understand what the anomaly means in physical/security terms
2. write_nist_incident_report — to draft a NIST SP 800-61 incident report
3. generate_suricata_rule — to create a Suricata rule blocking the malicious pattern

RULES:
- When writing the report, explicitly cite the IEC 62443 controls and past incidents from the RAG context by name (e.g., "SR 5.1 — Network Segmentation").
- The Suricata rule must use `alert modbus` protocol keyword, specify correct source and destination IPs, include a `sid:` unique to this alert, and target the specific Modbus function code observed.
- After all tools complete, print a one-paragraph summary of what was done and the file paths created.

SAFETY FIRST: You are responsible for protecting physical infrastructure. Always consider the physical impact (pump damage, tank overfill, cavitation) in your analysis."""


def _sid(alert_id: str) -> int:
    return 1_000_000 + (
        int(hashlib.sha256(alert_id.encode()).hexdigest()[:8], 16) % 9_000_000
    )


def _validate_rule(rule: str) -> str:
    if not re.match(r"alert\s+\w+\s+.*?\(", rule, re.DOTALL):
        return "FAILED: rule must match 'alert <protocol> ... (...)' pattern"
    if "sid:" not in rule:
        return "FAILED: rule must contain sid:"
    if "classtype:" not in rule:
        return "FAILED: rule must contain classtype:"
    if "msg:" not in rule:
        return "FAILED: rule must contain msg:"
    if "modbus" not in rule:
        return "FAILED: rule must use modbus protocol keyword"
    return "PASSED"


@tool
def analyze_anomaly(
    anomaly_score: float,
    tank_level_mean: float,
    tank_level_max: float,
    has_write_fc: bool,
    function_codes: list[int],
    source_ips: list[str],
    plc_ip: str,
) -> str:
    """Analyze an OT anomaly and produce a structured natural-language assessment of what it means in physical and security terms."""
    fcs = function_codes
    parts = []
    title = ""
    description = ""
    impact = ""
    mitre = ""
    anomaly_type = ""

    if has_write_fc and tank_level_mean < 10:
        anomaly_type = "UNAUTHORIZED_WRITE_WITH_CAVITATION"
        title = "Unauthorized Write Causing Cavitation Risk"
        description = (
            f"An unauthorized Modbus write from {source_ips} to {plc_ip} "
            f"combined with critically low tank level ({tank_level_mean}%) "
            f"indicates a targeted attack that closed the inlet valve, "
            f"cutting water flow and creating cavitation risk."
        )
        impact = (
            "Pump cavitation causes mechanical damage (erosion of impeller "
            "blades, bearing failure) and loss of water pressure to "
            "downstream processes."
        )
        mitre = "T0836 — Modbus Function Code Abuse, T0815 — Denial of View"
    elif has_write_fc:
        anomaly_type = "UNAUTHORIZED_MODBUS_WRITE"
        title = "Unauthorized Modbus Write Command"
        description = (
            f"A Modbus write command (FC 6) from {source_ips} to {plc_ip} "
            f"was observed. The engineering workstation (172.23.0.4) is the "
            f"only authorized write source. Source(s) {source_ips} include "
            f"an IP not in the authorized write allow-list."
        )
        impact = (
            "Write commands can alter PLC register values, changing valve "
            "states, setpoints, and control logic. Potential consequences "
            "include tank overfill, pump damage, or process shutdown."
        )
        mitre = "T0836 — Modbus Function Code Abuse"
    elif 131 in fcs:
        if tank_level_max > 80:
            anomaly_type = "OVERFILL_WITH_SCANNING"
            title = "Tank Overfill with Network Scanning"
            description = (
                f"Modbus exception responses (FC 131) detected from "
                f"{source_ips} targeting {plc_ip}, while tank level reached "
                f"{tank_level_max}% (overfill threshold: >80%). This pattern "
                f"suggests reconnaissance probing combined with a process "
                f"abnormality — possibly staged for a follow-on attack."
            )
            impact = (
                "Overfill can cause water damage, environmental spill, and "
                "regulatory fines. The scanning indicates active "
                "reconnaissance, raising the overall threat level."
            )
            mitre = "T0846 — Remote System Information Discovery, T0836 — Modbus Function Code Abuse"
        else:
            anomaly_type = "NETWORK_SCANNING"
            title = "Modbus Network Reconnaissance Scan"
            description = (
                f"A burst of Modbus exception responses (FC 131) from "
                f"{source_ips} to {plc_ip} indicates network scanning. "
                f"The attacker is probing invalid register addresses to map "
                f"the PLC's register layout and identify unsecured functions."
            )
            impact = (
                "Reconnaissance is a precursor to targeted attack. Once "
                "register mappings are identified, the attacker can craft "
                "precise write commands to manipulate physical processes."
            )
            mitre = "T0846 — Remote System Information Discovery"
    elif tank_level_max > 85:
        anomaly_type = "TANK_OVERFILL"
        title = "Tank Level Critical Overfill"
        description = (
            f"Tank level peaked at {tank_level_max}% on {plc_ip}, exceeding "
            f"the normal maximum of 85%. This could indicate a stuck-open "
            f"inlet valve, a failed control loop, or active tampering with "
            f"register values."
        )
        impact = (
            "Overfill causes water spill, equipment damage, and potential "
            "safety hazard. In a water treatment plant, this can lead to "
            "untreated water release."
        )
        mitre = "T0815 — Denial of View (if sensor values are manipulated)"
    elif tank_level_mean < 15:
        anomaly_type = "CAVITATION_RISK"
        title = "Low Tank Level — Cavitation Risk"
        description = (
            f"Tank level dropped to mean {tank_level_mean}% on {plc_ip} "
            f"(critical threshold: <15%). This creates cavitation risk for "
            f"downstream pumps, which can cause severe mechanical damage."
        )
        impact = (
            "Cavitation erodes pump impellers, damages seals and bearings, "
            "and can lead to complete pump failure and loss of water pressure."
        )
        mitre = "T0815 — Denial of View, T0836 — Modbus Function Code Abuse"
    else:
        anomaly_type = "GENERIC_ANOMALY"
        title = "Unclassified Process Anomaly"
        description = (
            f"An anomaly was detected on {plc_ip} with score "
            f"{anomaly_score:.4f}. Tank level (mean={tank_level_mean}%, "
            f"max={tank_level_max}%) deviates from expected patterns but "
            f"does not match known attack signatures."
        )
        impact = "Low confidence anomaly. Further investigation recommended."
        mitre = "N/A"

    parts.append(f"## Analysis: {title}")
    parts.append(f"**Anomaly Score:** {anomaly_score:.4f}")
    parts.append(f"**Type:** {anomaly_type}")
    parts.append(f"**Assessment:** {description}")
    parts.append(f"**Potential Impact:** {impact}")
    parts.append(f"**MITRE ATT&CK for ICS:** {mitre}")
    parts.append(f"**Function Codes Observed:** {fcs}")
    parts.append(f"**Source IPs:** {source_ips}")
    parts.append(f"**Tank Level:** mean={tank_level_mean}%, max={tank_level_max}%")

    return "\n\n".join(parts)


@tool
def write_nist_incident_report(
    alert_id: str,
    plc_ip: str,
    anomaly_score: float,
    analysis_summary: str,
    rag_context: str,
    function_codes: list[int],
    source_ips: list[str],
    tank_level_mean: float,
    tank_level_max: float,
) -> str:
    """Draft a NIST SP 800-61 incident report from the alert data, RAG context, and analysis summary. Writes to outputs/incident_{alert_id}.md."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    incident_id = f"INC-{alert_id[:8].upper()}"

    report = f"""# NIST Incident Report: {incident_id}

**Generated by:** OT SOC Analyst L1 Agent
**Generated at:** {now}
**Report ID:** {incident_id}

---

## 1. Incident Summary

An anomaly was detected on PLC at {plc_ip} (alert ID: {alert_id}). The ML anomaly detection engine flagged a window with anomaly score {anomaly_score:.4f}. After enrichment and analysis, the following assessment was produced:

{analysis_summary}

---

## 2. Affected Assets

| Asset | IP Address | Role |
|-------|-----------|------|
| plc_intake | {plc_ip} | Water intake control, Level 1 Control Zone |

**Source IPs Observed During Window:** {", ".join(source_ips)}

---

## 3. Observed Activity

- **Anomaly Score:** {anomaly_score:.4f}
- **Function Codes:** {function_codes}
- **Tank Level (mean):** {tank_level_mean}%
- **Tank Level (max):** {tank_level_max}%
- **Write FC Observed:** {"Yes" if 6 in function_codes else "No"}
- **Exception Responses (FC 131):** {"Yes" if 131 in function_codes else "No"}

---

## 4. Potential Impact

Based on the analysis and applicable IEC 62443 controls from the knowledge base:

{rag_context}

---

## 5. Recommended Actions

1. **Immediate:** Verify the current tank level and valve status on plc_intake via the HMI (172.22.0.10).
2. **Containment:** Block the suspicious source IP(s) at the OT zone boundary firewall.
3. **Detection:** Deploy the generated Suricata rule to the IDS sensor.
4. **Investigation:** Review recent Modbus logs for additional scanning or write attempts from the same source.
5. **Recovery:** If tank level is abnormal, return to normal operating range by adjusting the inlet valve through the authorized engineering workstation (172.23.0.4).
6. **Post-Incident:** Update the asset inventory and access control lists if a new authorized source was missed.

---

## 6. References

- NIST SP 800-61 Rev 2
- MITRE ATT&CK for ICS
- OT-Security-Lab incident response playbooks

---

*This report was automatically generated by the OT SOC Agent. All recommendations should be reviewed by a human analyst before action.*
"""
    output_path = OUTPUTS_DIR / f"incident_{alert_id}.md"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report)
    return str(output_path)


@tool
def generate_suricata_rule(
    source_ip: str,
    destination_ip: str,
    function_code: int,
    has_write_fc: bool,
    alert_id: str,
) -> str:
    """Generate a Suricata rule to block the malicious Modbus pattern. Validates the rule structure and returns the file path."""
    sid = _sid(alert_id)

    if function_code == 6 and has_write_fc:
        content = 'content:"|00 06|";'
        cls = "attempted-admin"
        msg = f"OT SOC - Unauthorized Modbus Write from {source_ip} to {destination_ip}"
    elif function_code == 131:
        content = 'content:"|00 83|";'
        cls = "attempted-recon"
        msg = f"OT SOC - Modbus Exception Scan from {source_ip} to {destination_ip}"
    elif function_code == 3:
        content = 'content:"|00 03|";'
        cls = "unknown"
        msg = f"OT SOC - Anomalous Modbus Read from {source_ip} to {destination_ip}"
    else:
        content = ""
        cls = "unknown"
        msg = f"OT SOC - Anomalous Modbus Traffic from {source_ip} to {destination_ip}"

    rule = f"""alert modbus $EXTERNAL_NET any -> $HOME_NET 502 (
    msg:"{msg}";
    {content}
    flow:to_server;
    sid:{sid};
    classtype:{cls};
    rev:1;
    metadata:alert_id {alert_id};)"""

    validation = _validate_rule(rule)

    output_path = OUTPUTS_DIR / f"block_{alert_id}.rules"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rule + "\n")

    result = (
        f"Rule written to {output_path}\n"
        f"SID: {sid}\n"
        f"Validation: {validation}\n\n"
        f"```\n{rule}\n```"
    )
    return result


def run_agent(alert: dict) -> dict:
    """Execute the full agent pipeline on a single alert.

    Returns dict with keys:
        summary        — one-paragraph summary of what was done
        incident_path  — path to the written incident report (or None)
        rule_path      — path to the written Suricata rule (or None)
    """
    alert_id = alert.get("alert_id", "unknown")

    print(f"Loading RAG context for alert {alert_id[:8]}...", file=sys.stderr)
    rag_context = retrieve_context(alert)

    base_url = os.environ.get("OPENAI_BASE_URL", None)
    model = ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0,
        base_url=base_url,
    )
    tools = [analyze_anomaly, write_nist_incident_report, generate_suricata_rule]
    agent = create_agent(model, tools, system_prompt=SYSTEM_PROMPT)

    alert_str = json.dumps(alert, indent=2, default=str)
    user_msg = (
        f"## Alert Data\n```json\n{alert_str}\n```\n\n## RAG Context\n{rag_context}"
    )

    print(f"Invoking agent for alert {alert_id[:8]}...", file=sys.stderr)
    result = agent.invoke(
        {"messages": [("user", user_msg)]},
        {"recursion_limit": 50},
    )

    summary = ""
    incident_path = None
    rule_path = None
    for msg in result["messages"]:
        if msg.type == "ai" and msg.content:
            summary = msg.content
    for msg in result["messages"]:
        if msg.type == "tool" and "incident_" in getattr(msg, "content", ""):
            match = re.search(r"/outputs/incident_\S+\.md", msg.content)
            if match:
                incident_path = match.group(0)
        if msg.type == "tool" and "block_" in getattr(msg, "content", ""):
            match = re.search(r"/outputs/block_\S+\.rules", msg.content)
            if match:
                rule_path = match.group(0)

    return {
        "summary": summary,
        "incident_path": incident_path,
        "rule_path": rule_path,
    }


def main():
    parser = argparse.ArgumentParser(
        description="OT SOC Analyst Agent — analyze alerts, write NIST reports, generate Suricata rules."
    )
    parser.add_argument(
        "--alert",
        type=str,
        default=None,
        help="Path to a single alert JSON file. If omitted, read JSON from stdin.",
    )
    args = parser.parse_args()

    if args.alert:
        alert_path = Path(args.alert)
        if not alert_path.exists():
            print(f"Error: alert file not found: {alert_path}", file=sys.stderr)
            sys.exit(1)
        with open(alert_path) as f:
            alert = json.load(f)
    else:
        alert = json.load(sys.stdin)

    result = run_agent(alert)
    print(result["summary"])
    print(f"\nAll outputs written to {OUTPUTS_DIR}/")


if __name__ == "__main__":
    main()
