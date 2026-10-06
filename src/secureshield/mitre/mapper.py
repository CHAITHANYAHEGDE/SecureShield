"""
secureshield.mitre.mapper
==========================
Behavior-based MITRE ATT&CK mapping.

CRITICAL PRINCIPLE:
  Techniques are mapped ONLY when behavioral evidence supports the mapping.
  A positive ML prediction alone does NOT justify a MITRE technique mapping.
  Each mapping requires supporting ForensicEvent IDs and explicit rationale.

This implements the mapping layer described in Section 13 of the research spec.

Reference: MITRE ATT&CK Framework v14.1
  https://attack.mitre.org/

Mapping confidence levels:
  - HIGH (0.8-1.0): Strong behavioral evidence from multiple events
  - MEDIUM (0.5-0.79): Partial evidence, some indicators present
  - LOW (0.3-0.49): Weak signals, requires further investigation

Limitations (per LIMITATIONS.md):
  - CIC-MalMem-2022 provides aggregate Volatility statistics, not raw events.
  - Synthetic events derived from features have lower mapping confidence.
  - Sub-technique precision requires real endpoint telemetry.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from secureshield.forensics.schema import CorrelatedIncident, EventType, ForensicEvent
from secureshield.common.logging_utils import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping rules
# ---------------------------------------------------------------------------

# Each rule: (technique_id, technique_name, tactic, sub_technique, trigger_event_types, min_confidence, rationale)
MAPPING_RULES: List[Dict[str, Any]] = [
    {
        "technique_id": "T1055",
        "technique": "Process Injection",
        "tactic": "Defense Evasion / Privilege Escalation",
        "sub_technique": None,
        "trigger_event_types": [EventType.PROCESS_INJECTION],
        "trigger_feature_keys": ["malfind.ninjections", "malfind.uniqueInjections"],
        "min_evidence_value": 1.0,
        "min_confidence": 0.70,
        "rationale_template": (
            "Process injection indicators detected: {evidence_summary}. "
            "Memory regions with executable permissions and injection counts suggest "
            "code injection into remote process memory (T1055)."
        ),
    },
    {
        "technique_id": "T1055.012",
        "technique": "Process Injection: Process Hollowing",
        "tactic": "Defense Evasion",
        "sub_technique": "T1055.012",
        "trigger_event_types": [EventType.PROCESS_INJECTION, EventType.MEMORY_COMMIT],
        "trigger_feature_keys": ["malfind.commitCharge", "malfind.ninjections"],
        "min_evidence_value": 2.0,
        "min_confidence": 0.65,
        "rationale_template": (
            "High commit charge ({evidence_summary}) combined with injection indicators "
            "suggests process hollowing: legitimate process unmapped and replaced with payload."
        ),
    },
    {
        "technique_id": "T1036",
        "technique": "Masquerading",
        "tactic": "Defense Evasion",
        "sub_technique": None,
        "trigger_event_types": [EventType.DLL_HIDING, EventType.PROCESS_HIDING],
        "trigger_feature_keys": ["ldrmodules.not_in_load", "ldrmodules.not_in_init"],
        "min_evidence_value": 0.5,
        "min_confidence": 0.60,
        "rationale_template": (
            "DLL not present in expected module lists ({evidence_summary}): "
            "indicates DLL hiding/masquerading to evade memory scanners (T1036)."
        ),
    },
    {
        "technique_id": "T1014",
        "technique": "Rootkit",
        "tactic": "Defense Evasion",
        "sub_technique": None,
        "trigger_event_types": [EventType.KERNEL_CALLBACK, EventType.PROCESS_HIDING],
        "trigger_feature_keys": ["psxview.not_in_pslist", "callbacks.ncallbacks"],
        "min_evidence_value": 1.0,
        "min_confidence": 0.75,
        "rationale_template": (
            "Process hiding and kernel callback indicators detected ({evidence_summary}): "
            "characteristic of rootkit behavior (T1014). Process not visible in standard "
            "process list despite active in system."
        ),
    },
    {
        "technique_id": "T1543",
        "technique": "Create or Modify System Process",
        "tactic": "Persistence / Privilege Escalation",
        "sub_technique": None,
        "trigger_event_types": [EventType.SERVICE_CREATION],
        "trigger_feature_keys": ["svcscan.nservices", "svcscan.nactive"],
        "min_evidence_value": 1.0,
        "min_confidence": 0.55,
        "rationale_template": (
            "Service creation indicators: {evidence_summary}. "
            "Elevated service count may indicate malware establishing persistence "
            "via Windows service (T1543)."
        ),
    },
    {
        "technique_id": "T1071",
        "technique": "Application Layer Protocol",
        "tactic": "Command and Control",
        "sub_technique": None,
        "trigger_event_types": [EventType.NETWORK_CONNECTION, EventType.DNS_QUERY],
        "trigger_feature_keys": [],
        "min_evidence_value": 0.0,
        "min_confidence": 0.60,
        "rationale_template": (
            "Network communication observed to external destination ({evidence_summary}): "
            "consistent with C2 communication via application layer protocol (T1071)."
        ),
    },
    {
        "technique_id": "T1620",
        "technique": "Reflective Code Loading",
        "tactic": "Defense Evasion",
        "sub_technique": None,
        "trigger_event_types": [EventType.DLL_HIDING, EventType.PROCESS_INJECTION],
        "trigger_feature_keys": ["ldrmodules.not_in_mem", "ldrmodules.not_in_mem_avg"],
        "min_evidence_value": 0.5,
        "min_confidence": 0.65,
        "rationale_template": (
            "DLL not in memory module list ({evidence_summary}): "
            "indicates reflective loading of code not registered with Windows loader (T1620)."
        ),
    },
    {
        "technique_id": "T1059",
        "technique": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "sub_technique": None,
        "trigger_event_types": [EventType.PROCESS_CREATION],
        "trigger_feature_keys": [],
        "min_evidence_value": 0.0,
        "min_confidence": 0.50,
        "rationale_template": (
            "Command execution activity observed ({evidence_summary}): "
            "consistent with scripting interpreter usage for execution (T1059)."
        ),
    },
]


# ---------------------------------------------------------------------------
# MITRE Mapper
# ---------------------------------------------------------------------------

class MITREMapper:
    """
    Maps forensic evidence and ML detections to MITRE ATT&CK techniques.

    Requires behavioral evidence to support each mapping.
    An ML "malicious" label alone is insufficient for technique attribution.
    """

    def __init__(
        self,
        require_evidence: bool = True,
        min_confidence: float = 0.50,
    ):
        self.require_evidence = require_evidence
        self.min_confidence = min_confidence
        self.mappings_: List[Dict[str, Any]] = []

    def map_incident(self, incident: CorrelatedIncident) -> List[Dict[str, Any]]:
        """
        Attempt MITRE ATT&CK mappings for a correlated incident.

        Each mapping requires:
          1. At least one supporting event of the trigger event type
          2. Confidence above min_confidence
          3. Explicit rationale citing event IDs

        Args:
            incident: Correlated incident to analyze.

        Returns:
            List of MITRE ATT&CK mapping dicts.
        """
        mappings = []
        events = incident.events

        if not events:
            return []

        # ML confidence (if available — as supporting signal, not primary evidence)
        ml_events = [e for e in events if e.event_type == EventType.ML_DETECTION]
        ml_confidence = (
            max((e.ml_confidence or 0.0 for e in ml_events), default=0.0)
            if ml_events else 0.0
        )

        for rule in MAPPING_RULES:
            trigger_types = rule["trigger_event_types"]
            trigger_features = rule.get("trigger_feature_keys", [])
            rule_min_conf = rule["min_confidence"]

            # Find supporting events
            supporting_events = [
                e for e in events
                if e.event_type in trigger_types
            ]

            # Find supporting feature evidence
            feature_evidence = []
            for e in events:
                if e.raw_feature_values:
                    for fk in trigger_features:
                        val = e.raw_feature_values.get(fk, 0.0)
                        if val and val >= rule.get("min_evidence_value", 0.0):
                            feature_evidence.append(
                                {"feature": fk, "value": val, "event_id": e.event_id}
                            )

            if self.require_evidence and not supporting_events and not feature_evidence:
                continue

            # Compute mapping confidence
            event_confidence = (
                sum(e.confidence for e in supporting_events) / len(supporting_events)
                if supporting_events else 0.0
            )
            # ML confidence as partial booster (not determinant)
            mapping_confidence = min(
                1.0,
                event_confidence * 0.7 + ml_confidence * 0.3
            )

            if mapping_confidence < self.min_confidence:
                continue

            # Build evidence summary
            evidence_summary = "; ".join([
                f"event {e.event_id} ({e.event_type.value})"
                for e in supporting_events[:3]
            ])
            if feature_evidence:
                feature_summary = ", ".join([
                    f"{fe['feature']}={fe['value']:.1f}" for fe in feature_evidence[:3]
                ])
                evidence_summary += f"; features: {feature_summary}"

            rationale = rule["rationale_template"].format(
                evidence_summary=evidence_summary or "behavioral indicators"
            )

            mapping = {
                "technique_id": rule["technique_id"],
                "technique": rule["technique"],
                "tactic": rule["tactic"],
                "sub_technique": rule.get("sub_technique"),
                "supporting_events": [e.event_id for e in supporting_events],
                "feature_evidence": feature_evidence[:5],
                "ml_confidence_used": round(ml_confidence, 4),
                "mapping_confidence": round(mapping_confidence, 4),
                "rationale": rationale,
                "mapping_basis": (
                    "behavioral_evidence" if supporting_events
                    else "feature_evidence_only" if feature_evidence
                    else "ml_only"
                ),
                "note": (
                    "Mapping based on behavioral evidence from forensic events. "
                    "Sub-technique precision requires real endpoint telemetry."
                    if incident.contains_synthetic_events
                    else "Mapping based on real forensic evidence."
                ),
            }
            mappings.append(mapping)

        # Sort by confidence
        mappings.sort(key=lambda x: x["mapping_confidence"], reverse=True)
        self.mappings_ = mappings

        logger.info(f"Mapped {len(mappings)} MITRE ATT&CK techniques for {incident.incident_id}")
        return mappings

    def get_tactic_coverage(self) -> Dict[str, List[str]]:
        """Return techniques grouped by tactic."""
        coverage: Dict[str, List[str]] = {}
        for m in self.mappings_:
            tactic = m["tactic"]
            if tactic not in coverage:
                coverage[tactic] = []
            coverage[tactic].append(m["technique_id"])
        return coverage
