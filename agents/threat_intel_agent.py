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

from dataclasses import dataclass
import json
import sys
from pathlib import Path
from typing import Mapping, Sequence

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from common.events import (
    SOCEvent,
    StageName,
    ThreatIntelligenceMetadata,
    severity_with_threat_evidence,
)

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


@dataclass(frozen=True)
class MitreMatch:
    technique: str
    tactic: str
    confidence: float
    action: str
    match_type: str


class ThreatIntelProcessor:
    """Map observed or predicted attacks to the existing MITRE knowledge base."""

    def __init__(
        self,
        knowledge_base: Mapping[str, Mapping] = MITRE_KB,
        fuzzy_keywords: Sequence[tuple[str, Mapping]] = FUZZY_KEYWORDS,
    ) -> None:
        self.knowledge_base = knowledge_base
        self.fuzzy_keywords = fuzzy_keywords

    @staticmethod
    def _match(entry: Mapping, match_type: str, confidence: float | None = None):
        return MitreMatch(
            technique=str(entry["technique"]),
            tactic=str(entry["tactic"]),
            confidence=float(entry["confidence"] if confidence is None else confidence),
            action=str(entry["action"]),
            match_type=match_type,
        )

    def lookup(self, event: str, predicted_attack: str | None = None) -> MitreMatch:
        if event in self.knowledge_base:
            return self._match(self.knowledge_base[event], "exact_match")

        if predicted_attack and predicted_attack in self.knowledge_base:
            entry = self.knowledge_base[predicted_attack]
            confidence = round(float(entry["confidence"]) * 0.85, 2)
            return self._match(entry, "predicted_attack_match", confidence)

        event_lower = event.lower()
        for keyword, entry in self.fuzzy_keywords:
            if keyword in event_lower:
                return self._match(entry, "fuzzy_keyword_match")

        return self._match(UNKNOWN_TECHNIQUE, "unknown")

    def process(self, event: SOCEvent) -> SOCEvent:
        intel = self.lookup(
            event.event,
            event.investigation_metadata.predicted_next_attack,
        )
        enriched = event.model_copy(deep=True)
        enriched.threat_intelligence = ThreatIntelligenceMetadata(
            mitre_attack=intel.technique,
            mitre_tactic=intel.tactic,
            confidence=intel.confidence,
            recommended_action=intel.action,
            method=intel.match_type,
        )
        enriched.severity = severity_with_threat_evidence(
            enriched.severity,
            tactic=intel.tactic,
            confidence=intel.confidence,
            match_type=intel.match_type,
            failed_login_count=enriched.detection.failed_login_count,
        )
        return enriched.advance_stage(StageName.THREAT_INTEL, "threat-intel-agent")


def lookup_mitre(event: str, predicted_attack: str | None = None) -> MitreMatch:
    """Compatibility wrapper around the deterministic lookup processor."""

    return ThreatIntelProcessor().lookup(event, predicted_attack)


def process_event(event: SOCEvent) -> SOCEvent:
    """Compatibility wrapper for deterministic threat-intel processing."""

    return ThreatIntelProcessor().process(event)


def main() -> None:
    from backend.database import init_db, persist_event
    from common.health import start_health_server
    from common.kafka import (
        consume_forever,
        create_consumer,
        create_producer,
        publish_event,
    )
    from common.pipeline import run_stage

    health = start_health_server("threat-intel-agent")
    processor = ThreatIntelProcessor()
    consumer = create_consumer("investigated_alerts", "soc-threat-intel")
    producer = create_producer()
    init_db()
    health.set_ready(processor="mitre-mapping")
    print("Threat Intelligence Agent Running...\n")

    def handle(payload: dict) -> None:
        event = run_stage(
            payload,
            processor,
            persist_event,
            publish=lambda value: publish_event(
                producer,
                "threat_enriched_alerts",
                value,
            ),
        )
        print(json.dumps(event.to_message(), default=str), flush=True)

    consume_forever(consumer, handle, "threat-intel-agent")


if __name__ == "__main__":
    main()
