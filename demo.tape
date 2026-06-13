Output demo.gif
Set FontSize 16
Set Theme Dracula
Set TypingSpeed 30ms
Set Width 1000
Set Height 600
Set Framerate 10

# 1. Start webhook receiver via venv
Type "venv/bin/uvicorn scripts.webhook_receiver:app --host 0.0.0.0 --port 8000 &"
Enter
Sleep 3s

Ctrl+l
Sleep 1s

# 2. Send alert — agent runs inline
Type 'curl -s -X POST http://localhost:8000/alert -H "Content-Type: application/json" -d @sample_alert.json | venv/bin/python -m json.tool'
Enter

# Wait for LLM agent to finish (10-15s)
Require "rule_path"
Sleep 2s

Ctrl+l
Sleep 1s

# 3. Show the NIST incident report
Type "# Incident report (NIST SP 800-61):"
Enter
Type "cat outputs/incident_e8358fb5-*.md"
Enter
Sleep 4s

# 4. Show the Suricata rule
Type "# Suricata rule:"
Enter
Type "cat outputs/block_e8358fb5-*.rules"
Enter
Sleep 2s

Ctrl+l
Sleep 1s

# 5. Run deterministic tests
Type "# Running tests (no API key needed, no network):"
Enter
Type "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 venv/bin/python -m pytest tests/ -v"
Enter
Sleep 12s
