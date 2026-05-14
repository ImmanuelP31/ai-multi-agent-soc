"""
Threat Intelligence Agent
--------------------------
Consumes investigated alerts and enriches each one with:
  - MITRE ATT&CK technique mapping
  - Technique confidence score (exact match vs fuzzy fallback)
  - Tactic category (what phase of the kill chain)
  - Recommended action based on technique
  - Predicted attack label from investigation agent (if available)

Handles unknown attack types via keyword-based fuzzy matching
instead of returning a blank "Unknown Technique".
"""

import json
import os
import sys
from pathlib import Path

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from kafka import KafkaConsumer, KafkaProducer

# =========================================================
# MITRE ATT&CK KNOWLEDGE BASE
# =========================================================
# Structure: event_key → {technique, tactic, confidence, action}

MITRE_KB: dict[str, dict] = {
    # --- Credential Access ---
    "failed_login": {
        "technique":  "T1110 – Brute Force",
        "tactic":     "Credential Access",
        "confidence": 0.95,
        "action":     "Enforce account lockout policy; block source IP after threshold.",
    },
    "Web Attack – Brute Force": {
        "technique":  "T1110.001 – Password Guessing",
        "tactic":     "Credential Access",
        "confidence": 0.95,
        "action":     "Rate-limit login endpoints; enable MFA.",
    },
    "FTP-Patator": {
        "technique":  "T1110.001 – Password Guessing (FTP)",
        "tactic":     "Credential Access",
        "confidence": 0.92,
        "action":     "Disable anonymous FTP; enforce key-based authentication.",
    },
    "SSH-Patator": {
        "technique":  "T1110.001 – Password Guessing (SSH)",
        "tactic":     "Credential Access",
        "confidence": 0.92,
        "action":     "Switch to SSH key-based auth; block offending IPs via fail2ban.",
    },

    # --- Discovery ---
    "port_scan": {
        "technique":  "T1046 – Network Service Discovery",
        "tactic":     "Discovery",
        "confidence": 0.93,
        "action":     "Block scanning IP at perimeter firewall; alert SOC analyst.",
    },

    # --- Execution ---
    "malware_detected": {
        "technique":  "T1204 – User Execution",
        "tactic":     "Execution",
        "confidence": 0.90,
        "action":     "Isolate affected host; run full AV scan; preserve forensic image.",
    },

    # --- Privilege Escalation ---
    "privilege_escalation": {
        "technique":  "T1068 – Exploitation for Privilege Escalation",
        "tactic":     "Privilege Escalation",
        "confidence": 0.91,
        "action":     "Revoke elevated session; patch vulnerable service; audit sudo logs.",
    },

    # --- Initial Access ---
    "unauthorized_access": {
        "technique":  "T1078 – Valid Accounts (Compromised)",
        "tactic":     "Initial Access",
        "confidence": 0.88,
        "action":     "Force password reset for affected account; review access logs.",
    },

    # --- Impact (DoS) ---
    "ddos_attempt": {
        "technique":  "T1498 – Network Denial of Service",
        "tactic":     "Impact",
        "confidence": 0.94,
        "action":     "Activate DDoS mitigation; enable rate limiting; notify upstream ISP.",
    },
    "DDoS": {
        "technique":  "T1498 – Network Denial of Service",
        "tactic":     "Impact",
        "confidence": 0.94,
        "action":     "Activate DDoS mitigation; enable rate limiting; notify upstream ISP.",
    },
    "DoS slowloris": {
        "technique":  "T1499.001 – OS Exhaustion Flood",
        "tactic":     "Impact",
        "confidence": 0.90,
        "action":     "Tune server connection timeouts; deploy reverse proxy with request limits.",
    },
    "DoS Slowhttptest": {
        "technique":  "T1499.001 – OS Exhaustion Flood",
        "tactic":     "Impact",
        "confidence": 0.90,
        "action":     "Tune server connection timeouts; deploy reverse proxy with request limits.",
    },
    "DoS Hulk": {
        "technique":  "T1499.002 – Service Exhaustion Flood",
        "tactic":     "Impact",
        "confidence": 0.91,
        "action":     "Enable connection throttling; scale horizontally; block offending IPs.",
    },
    "DoS GoldenEye": {
        "technique":  "T1499.002 – Service Exhaustion Flood",
        "tactic":     "Impact",
        "confidence": 0.91,
        "action":     "Enable connection throttling; scale horizontally; block offending IPs.",
    },

    # --- Collection / Exfiltration ---
    "Bot": {
        "technique":  "T1071 – Application Layer Protocol (C2)",
        "tactic":     "Command and Control",
        "confidence": 0.87,
        "action":     "Isolate host; investigate outbound connections; check for C2 beaconing.",
    },
    "Infiltration": {
        "technique":  "T1570 – Lateral Tool Transfer",
        "tactic":     "Lateral Movement",
        "confidence": 0.86,
        "action":     "Segment network; revoke cross-host credentials; audit SMB/RDP logs.",
    },

    # --- Web attacks ---
    "Web Attack – XSS": {
        "technique":  "T1059.007 – JavaScript Injection",
        "tactic":     "Execution",
        "confidence": 0.89,
        "action":     "Sanitise user input; enforce Content Security Policy headers.",
    },
    "Web Attack – SQL Injection": {
        "technique":  "T1190 – Exploit Public-Facing Application",
        "tactic":     "Initial Access",
        "confidence": 0.93,
        "action":     "Parameterise all DB queries; review WAF rules; audit DB access logs.",
    },

    # --- Vulnerability ---
    "Heartbleed": {
        "technique":  "T1190 – Exploit Public-Facing Application (CVE-2014-0160)",
        "tactic":     "Initial Access",
        "confidence": 0.97,
        "action":     "Patch OpenSSL immediately; rotate all TLS certificates and session keys.",
    },

    # --- Recon ---
    "PortScan": {
        "technique":  "T1046 – Network Service Discovery",
        "tactic":     "Discovery",
        "confidence": 0.93,
        "action":     "Block scanning IP at perimeter firewall; alert SOC analyst.",
    },
}

# Keyword → technique fallback for unknown events
FUZZY_KEYWORDS: list[tuple[str, dict]] = [
    ("brute",     {"technique": "T1110 – Brute Force",                    "tactic": "Credential Access", "confidence": 0.60, "action": "Enforce account lockout and MFA."}),
    ("scan",      {"technique": "T1046 – Network Service Discovery",      "tactic": "Discovery",         "confidence": 0.60, "action": "Block scanning IP at firewall."}),
    ("dos",       {"technique": "T1498 – Network Denial of Service",      "tactic": "Impact",            "confidence": 0.60, "action": "Activate DDoS mitigation controls."}),
    ("ddos",      {"technique": "T1498 – Network Denial of Service",      "tactic": "Impact",            "confidence": 0.65, "action": "Activate DDoS mitigation controls."}),
    ("inject",    {"technique": "T1190 – Exploit Public-Facing App",      "tactic": "Initial Access",    "confidence": 0.58, "action": "Review WAF and sanitise inputs."}),
    ("malware",   {"technique": "T1204 – User Execution",                 "tactic": "Execution",         "confidence": 0.65, "action": "Isolate host and run AV scan."}),
    ("privilege", {"technique": "T1068 – Exploitation for Priv. Esc.",    "tactic": "Privilege Escalation","confidence": 0.62,"action": "Revoke elevated session immediately."}),
    ("login",     {"technique": "T1110 – Brute Force",                    "tactic": "Credential Access", "confidence": 0.55, "action": "Review auth logs; enforce lockout."}),
    ("access",    {"technique": "T1078 – Valid Accounts",                 "tactic": "Initial Access",    "confidence": 0.50, "action": "Audit account activity."}),
]

UNKNOWN_TECHNIQUE = {
    "technique":  "T0000 – Unclassified Technique",
    "tactic":     "Unknown",
    "confidence": 0.30,
    "action":     "Manual analyst review required — no matching MITRE technique found.",
}


def lookup_mitre(event: str, predicted_attack: str | None = None) -> dict:
    """
    1. Exact match on event name
    2. Exact match on predicted_attack from LSTM
    3. Fuzzy keyword match on event name
    4. Unknown fallback
    """
    # Exact match
    if event in MITRE_KB:
        return MITRE_KB[event]

    # Use LSTM prediction if available
    if predicted_attack and predicted_attack in MITRE_KB:
        entry = MITRE_KB[predicted_attack].copy()
        entry["confidence"] = round(entry["confidence"] * 0.85, 2)  # slight penalty
        entry["note"] = f"Mapped via LSTM-predicted attack: {predicted_attack}"
        return entry

    # Fuzzy keyword fallback
    event_lower = event.lower()
    for keyword, entry in FUZZY_KEYWORDS:
        if keyword in event_lower:
            result = entry.copy()
            result["note"] = f"Fuzzy-matched on keyword '{keyword}' — confidence reduced."
            return result

    return UNKNOWN_TECHNIQUE.copy()


# =========================================================
# KAFKA SETUP
# =========================================================

_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9094")

consumer = KafkaConsumer(
    "investigated_alerts",
    bootstrap_servers=_bootstrap,
    auto_offset_reset="earliest",
    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
)

producer = KafkaProducer(
    bootstrap_servers=_bootstrap,
    value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
)

print("Threat Intelligence Agent Running...\n")

# =========================================================
# MAIN CONSUMER LOOP
# =========================================================

for message in consumer:

    alert            = message.value
    event            = alert.get("event", "unknown")
    predicted_attack = alert.get("predicted_next_attack")

    intel = lookup_mitre(event, predicted_attack)

    alert["mitre_attack"]          = intel["technique"]
    alert["mitre_tactic"]          = intel["tactic"]
    alert["mitre_confidence"]      = intel["confidence"]
    alert["recommended_action"]    = intel["action"]
    alert["threat_intel_method"]   = "exact_match" if "note" not in intel else intel.get("note", "fuzzy")

    producer.send("threat_enriched_alerts", alert)
    print(json.dumps(alert, default=str), flush=True)