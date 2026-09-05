from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd

from agents.threat_intel_agent import MAPPING_VERSION, ThreatIntelProcessor
from common.events import (
    InvestigationMetadata,
    SOCEvent,
    ThreatIntelligenceMetadata,
    ThreatMatchType,
)
from common.labels import normalize_attack_label
from ml.sequence_detection.pipeline import SEQUENCE_FEATURES, prepare_source_frame


def make_event(event: str) -> SOCEvent:
    return SOCEvent.create_ingested(
        event=event,
        source_ip="192.0.2.40",
        user="intel-test",
        observed_at=datetime(2026, 9, 5, tzinfo=timezone.utc),
    )


def test_exact_mapping_is_structured_and_auditable():
    intel = ThreatIntelProcessor().lookup("port_scan")

    assert intel.technique_id == "T1046"
    assert intel.technique_name == "Network Service Discovery"
    assert intel.tactic == "Discovery"
    assert intel.match_type is ThreatMatchType.EXACT
    assert intel.mapping_version == MAPPING_VERSION
    assert 'event == "PortScan"' in intel.evidence


def test_predicted_class_mapping_records_its_source():
    intel = ThreatIntelProcessor().lookup("unmapped_event", "PortScan")

    assert intel.technique_id == "T1046"
    assert intel.match_type is ThreatMatchType.PREDICTED_CLASS
    assert intel.confidence == 0.79
    assert intel.evidence == 'predicted_next_attack == "PortScan"'


def test_fuzzy_mapping_records_the_matching_keyword():
    intel = ThreatIntelProcessor().lookup("suspicious brute activity")

    assert intel.technique_id == "T1110"
    assert intel.match_type is ThreatMatchType.FUZZY
    assert 'keyword "brute"' in intel.evidence


def test_unknown_mapping_never_looks_exact_or_invents_a_technique_id():
    intel = ThreatIntelProcessor().lookup("novel behavior")

    assert intel.technique_id is None
    assert intel.match_type is ThreatMatchType.UNKNOWN
    assert intel.confidence == 0.0
    assert intel.evidence == "no event, prediction, or keyword mapping matched"


def test_corrupted_and_variant_labels_share_one_normal_form():
    assert normalize_attack_label("Web Attack \ufffd Brute Force") == (
        "Web Attack - Brute Force"
    )
    assert normalize_attack_label(" Web Attack \u2013 Sql Injection ") == (
        "Web Attack - SQL Injection"
    )
    assert normalize_attack_label("port_scan") == "PortScan"


def test_training_preprocessing_uses_shared_label_normalization():
    data = {feature: [1.0] for feature in SEQUENCE_FEATURES}
    data["Label"] = ["Web Attack \ufffd Brute Force"]
    data["Source IP"] = ["192.0.2.10"]
    data["Destination IP"] = ["198.51.100.10"]
    frame = pd.DataFrame(data)

    prepared, _ = prepare_source_frame(frame, "legacy.csv")

    assert prepared["Label"].tolist() == ["Web Attack - Brute Force"]


def test_structured_output_serializes_match_type_and_mapping_version():
    event = make_event("unmapped_event")
    event.investigation_metadata = InvestigationMetadata(
        predicted_next_attack="Web Attack \ufffd Brute Force"
    )

    result = ThreatIntelProcessor().process(event)
    serialized = result.threat_intelligence.model_dump(mode="json")

    assert serialized["technique_id"] == "T1110.001"
    assert serialized["match_type"] == "predicted_class"
    assert serialized["mapping_version"] == MAPPING_VERSION
    assert "after normalizing" in serialized["evidence"]


def test_legacy_unknown_method_stays_unknown():
    intel = ThreatIntelligenceMetadata.model_validate(
        {
            "mitre_attack": "T0000 - Unclassified Technique",
            "mitre_tactic": "Unknown",
            "confidence": 0.30,
            "method": "unknown",
        }
    )

    assert intel.match_type is ThreatMatchType.UNKNOWN
    assert intel.match_type is not ThreatMatchType.EXACT
