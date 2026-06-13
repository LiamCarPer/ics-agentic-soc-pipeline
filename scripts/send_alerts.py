"""
send_alerts.py — Reads alerts.jsonl and POSTs each alert to the webhook receiver.

Usage:
    python scripts/send_alerts.py \\
        --input data/alerts.jsonl \\
        --endpoint http://localhost:8000/alert
"""

import argparse
import json
import sys
from pathlib import Path

import requests


def main():
    parser = argparse.ArgumentParser(
        description="Send alerts from a JSONL file to the webhook receiver."
    )
    parser.add_argument(
        "--input",
        type=str,
        default="data/alerts.jsonl",
        help="Path to JSONL file (default: data/alerts.jsonl)",
    )
    parser.add_argument(
        "--endpoint",
        type=str,
        default="http://localhost:8000/alert",
        help="Receiver URL (default: http://localhost:8000/alert)",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    successes = 0
    failures = 0

    with open(input_path) as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                alert = json.loads(line)
                resp = requests.post(args.endpoint, json=alert, timeout=10)
                if resp.status_code == 202:
                    successes += 1
                else:
                    failures += 1
                    print(
                        f"Alert {line_num}: HTTP {resp.status_code} "
                        f"({resp.json().get('detail', 'error')})"
                    )
            except json.JSONDecodeError as e:
                failures += 1
                print(f"Alert {line_num}: invalid JSON — {e}")
            except requests.RequestException as e:
                failures += 1
                print(f"Alert {line_num}: request failed — {e}")

    print(f"Sent {successes} alerts, {failures} failures")


if __name__ == "__main__":
    main()
