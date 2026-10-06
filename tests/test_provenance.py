import os
import json
import pytest
from pathlib import Path
from secureshield.mitre.mapper import MITREMapper
from secureshield.forensics.schema import CorrelatedIncident, ForensicEvent, EventType, SourceType

def test_no_technique_without_evidence():
    """
    Test that MITRE mapping NEVER maps a technique when there is zero behavioral evidence,
    even if ML confidence is 1.0 (100% malicious).
    """
    mapper = MITREMapper(require_evidence=True)
    
    # Create incident with NO behavioral events, only ML detection
    incident = CorrelatedIncident(incident_id="TEST-001")
    ml_event = ForensicEvent(
        event_type=EventType.ML_DETECTION,
        source_type=SourceType.ML_MODEL_OUTPUT,
        ml_prediction="malicious",
        ml_confidence=1.0,  # 100% certain it's malicious
        confidence=1.0
    )
    incident.add_event(ml_event)
    
    mappings = mapper.map_incident(incident)
    
    # Assert no techniques were mapped because there's no behavioral evidence
    assert len(mappings) == 0, f"Expected 0 mappings when only ML evidence exists, got {len(mappings)}"


def test_technique_with_evidence():
    """
    Test that MITRE mapping DOES map a technique when behavioral evidence is present.
    """
    mapper = MITREMapper(require_evidence=True)
    
    incident = CorrelatedIncident(incident_id="TEST-002")
    # Add a behavioral event (Process Injection)
    inj_event = ForensicEvent(
        event_type=EventType.PROCESS_INJECTION,
        source_type=SourceType.SYNTHETIC_FROM_ML_FEATURES,
        confidence=0.9,
        raw_feature_values={"malfind.ninjections": 5.0}
    )
    incident.add_event(inj_event)
    
    mappings = mapper.map_incident(incident)
    
    # Should map T1055 (Process Injection)
    assert len(mappings) > 0, "Expected mappings with behavioral evidence"
    tactic_ids = [m["technique_id"] for m in mappings]
    assert "T1055" in tactic_ids, "Expected T1055 mapped due to process injection event"
    
def test_schema_validation():
    """
    Test schema validation for Incident and Forensic Events.
    """
    # Event without required fields will throw ValidationError by Pydantic
    event = ForensicEvent(
        event_type=EventType.NETWORK_CONNECTION,
        source_type=SourceType.NETWORK_PCAP,
        dst_ip="8.8.8.8"
    )
    assert event.event_id is not None
    assert event.dst_ip == "8.8.8.8"
    assert event.synthetic is False
    
    # Synthetic source type should auto-flag synthetic=True
    synthetic_event = ForensicEvent(
        event_type=EventType.PROCESS_CREATION,
        source_type=SourceType.SYNTHETIC_FROM_ML_FEATURES
    )
    assert synthetic_event.synthetic is True
    assert "SYNTHETIC EVENT" in synthetic_event.notes
