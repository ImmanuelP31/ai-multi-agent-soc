"""Enrich investigated SOC events with auditable local ATT&CK mappings."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import sys
from typing import Mapping, Sequence

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from common.events import (
    SOCEvent,
    StageName,
    ThreatIntelligenceMetadata,
    ThreatMatchType,
    severity_with_threat_evidence,
)
from common.labels import normalize_attack_label


MAPPING_VERSION = "2026-09-project-v1"


@dataclass(frozen=True)
class TechniqueRule:
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    recommended_action: str


@dataclass(frozen=True)
class FuzzyRule:
    keyword: str
    technique: TechniqueRule
    confidence: float


MITRE_KB: dict[str, TechniqueRule] = {
    "failed_login": TechniqueRule(
        "T1110", "Brute Force", "Credential Access", 0.95,
        "Enforce account lockout policy; block the source IP after the threshold.",
    ),
    "Web Attack - Brute Force": TechniqueRule(
        "T1110.001", "Password Guessing", "Credential Access", 0.95,
        "Rate-limit login endpoints and enable MFA.",
    ),
    "FTP-Patator": TechniqueRule(
        "T1110.001", "Password Guessing", "Credential Access", 0.92,
        "Disable anonymous FTP and strengthen authentication controls.",
    ),
    "SSH-Patator": TechniqueRule(
        "T1110.001", "Password Guessing", "Credential Access", 0.92,
        "Require SSH key authentication and block repeated offending sources.",
    ),
    "PortScan": TechniqueRule(
        "T1046", "Network Service Discovery", "Discovery", 0.93,
        "Block the scanning source at the perimeter and alert an analyst.",
    ),
    "malware_detected": TechniqueRule(
        "T1204", "User Execution", "Execution", 0.90,
        "Isolate the affected host, scan it, and preserve forensic evidence.",
    ),
    "privilege_escalation": TechniqueRule(
        "T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", 0.91,
        "Revoke the elevated session, patch the service, and audit privilege logs.",
    ),
    "unauthorized_access": TechniqueRule(
        "T1078", "Valid Accounts", "Initial Access", 0.88,
        "Reset affected credentials and review account activity.",
    ),
    "DDoS": TechniqueRule(
        "T1498", "Network Denial of Service", "Impact", 0.94,
        "Activate DDoS mitigation, rate limiting, and upstream coordination.",
    ),
    "DoS slowloris": TechniqueRule(
        "T1499.003", "Application Exhaustion Flood", "Impact", 0.90,
        "Tune connection timeouts and enforce reverse-proxy request limits.",
    ),
    "DoS Slowhttptest": TechniqueRule(
        "T1499.003", "Application Exhaustion Flood", "Impact", 0.90,
        "Tune request timeouts and enforce reverse-proxy request limits.",
    ),
    "DoS Hulk": TechniqueRule(
        "T1499.003", "Application Exhaustion Flood", "Impact", 0.91,
        "Throttle application requests and block confirmed offending sources.",
    ),
    "DoS GoldenEye": TechniqueRule(
        "T1499.003", "Application Exhaustion Flood", "Impact", 0.91,
        "Throttle application requests and block confirmed offending sources.",
    ),
    "Bot": TechniqueRule(
        "T1071", "Application Layer Protocol", "Command and Control", 0.87,
        "Isolate the host and investigate outbound command-and-control traffic.",
    ),
    "Infiltration": TechniqueRule(
        "T1570", "Lateral Tool Transfer", "Lateral Movement", 0.86,
        "Segment the network and audit cross-host file and remote-access activity.",
    ),
    "Web Attack - XSS": TechniqueRule(
        "T1190", "Exploit Public-Facing Application", "Initial Access", 0.89,
        "Sanitize user input and review content-security and WAF controls.",
    ),
    "Web Attack - SQL Injection": TechniqueRule(
        "T1190", "Exploit Public-Facing Application", "Initial Access", 0.93,
        "Parameterize database queries and audit WAF and database access logs.",
    ),
    "Heartbleed": TechniqueRule(
        "T1190", "Exploit Public-Facing Application", "Initial Access", 0.97,
        "Patch OpenSSL and rotate affected TLS certificates and session keys.",
    ),
}


FUZZY_KEYWORDS: tuple[FuzzyRule, ...] = (
    FuzzyRule("brute", MITRE_KB["failed_login"], 0.60),
    FuzzyRule("scan", MITRE_KB["PortScan"], 0.60),
    FuzzyRule("ddos", MITRE_KB["DDoS"], 0.65),
    FuzzyRule("dos", MITRE_KB["DDoS"], 0.60),
    FuzzyRule("inject", MITRE_KB["Web Attack - SQL Injection"], 0.58),
    FuzzyRule("malware", MITRE_KB["malware_detected"], 0.65),
    FuzzyRule("privilege", MITRE_KB["privilege_escalation"], 0.62),
    FuzzyRule("login", MITRE_KB["failed_login"], 0.55),
    FuzzyRule("access", MITRE_KB["unauthorized_access"], 0.50),
)


class ThreatIntelProcessor:
    """Map observed or predicted classes to the versioned local rule set."""

    def __init__(
        self,
        knowledge_base: Mapping[str, TechniqueRule] = MITRE_KB,
        fuzzy_keywords: Sequence[FuzzyRule] = FUZZY_KEYWORDS,
        mapping_version: str = MAPPING_VERSION,
    ) -> None:
        self.knowledge_base = {
            normalize_attack_label(label): rule for label, rule in knowledge_base.items()
        }
        self.fuzzy_keywords = tuple(fuzzy_keywords)
        self.mapping_version = mapping_version

    def _metadata(
        self,
        rule: TechniqueRule,
        match_type: ThreatMatchType,
        evidence: str,
        confidence: float | None = None,
    ) -> ThreatIntelligenceMetadata:
        return ThreatIntelligenceMetadata(
            technique_id=rule.technique_id,
            technique_name=rule.technique_name,
            tactic=rule.tactic,
            mapping_version=self.mapping_version,
            match_type=match_type,
            confidence=rule.confidence if confidence is None else confidence,
            evidence=evidence,
            recommended_action=rule.recommended_action,
        )

    def lookup(
        self,
        event: str,
        predicted_attack: str | None = None,
    ) -> ThreatIntelligenceMetadata:
        normalized_event = normalize_attack_label(event)
        normalized_prediction = normalize_attack_label(predicted_attack)

        if normalized_event in self.knowledge_base:
            evidence = f'event == "{normalized_event}"'
            if event != normalized_event:
                evidence += f' after normalizing "{event}"'
            return self._metadata(
                self.knowledge_base[normalized_event], ThreatMatchType.EXACT, evidence
            )

        if normalized_prediction in self.knowledge_base:
            rule = self.knowledge_base[normalized_prediction]
            evidence = f'predicted_next_attack == "{normalized_prediction}"'
            if predicted_attack != normalized_prediction:
                evidence += f' after normalizing "{predicted_attack}"'
            return self._metadata(
                rule,
                ThreatMatchType.PREDICTED_CLASS,
                evidence,
                round(rule.confidence * 0.85, 2),
            )

        event_lower = normalized_event.casefold()
        for fuzzy_rule in self.fuzzy_keywords:
            if fuzzy_rule.keyword.casefold() in event_lower:
                return self._metadata(
                    fuzzy_rule.technique,
                    ThreatMatchType.FUZZY,
                    f'keyword "{fuzzy_rule.keyword}" matched normalized event name '
                    f'"{normalized_event}"',
                    fuzzy_rule.confidence,
                )

        return ThreatIntelligenceMetadata(
            technique_id=None,
            technique_name="Unclassified Technique",
            tactic="Unknown",
            mapping_version=self.mapping_version,
            match_type=ThreatMatchType.UNKNOWN,
            confidence=0.0,
            evidence="no event, prediction, or keyword mapping matched",
            recommended_action="Manual analyst review required.",
        )

    def process(self, event: SOCEvent) -> SOCEvent:
        intel = self.lookup(
            event.event, event.investigation_metadata.predicted_next_attack
        )
        enriched = event.model_copy(deep=True)
        enriched.threat_intelligence = intel
        enriched.severity = severity_with_threat_evidence(
            enriched.severity,
            tactic=intel.tactic,
            confidence=intel.confidence,
            match_type=intel.match_type,
            failed_login_count=enriched.detection.failed_login_count,
        )
        return enriched.advance_stage(StageName.THREAT_INTEL, "threat-intel-agent")


def lookup_mitre(
    event: str,
    predicted_attack: str | None = None,
) -> ThreatIntelligenceMetadata:
    """Compatibility wrapper around the deterministic lookup processor."""

    return ThreatIntelProcessor().lookup(event, predicted_attack)


def process_event(event: SOCEvent) -> SOCEvent:
    """Compatibility wrapper for deterministic threat-intel processing."""

    return ThreatIntelProcessor().process(event)


def main() -> None:
    from backend.database import init_db, persist_event
    from common.health import start_health_server
    from common.kafka import consume_forever, create_consumer, create_producer, publish_event
    from common.pipeline import run_stage

    health = start_health_server("threat-intel-agent")
    processor = ThreatIntelProcessor()
    consumer = create_consumer("investigated_alerts", "soc-threat-intel")
    producer = create_producer()
    init_db()
    health.set_ready(processor="mitre-mapping", mapping_version=MAPPING_VERSION)
    print("Threat Intelligence Agent Running...\n")

    def handle(payload: dict) -> None:
        event = run_stage(
            payload,
            processor,
            persist_event,
            publish=lambda value: publish_event(
                producer, "threat_enriched_alerts", value
            ),
        )
        print(json.dumps(event.to_message(), default=str), flush=True)

    consume_forever(consumer, handle, "threat-intel-agent")


if __name__ == "__main__":
    main()
