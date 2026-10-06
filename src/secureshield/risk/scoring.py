"""
secureshield.risk.scoring
==========================
Quantitative risk assessment and prioritization.

Calculates an aggregated risk score for a correlated incident based on:
  - MITRE ATT&CK technique severity
  - Evidence severity (highest individual event severity)
  - Asset criticality (host context)
  - ML detection confidence
  - Attack graph centrality (how deeply rooted the attack is)

Risk formula:
  RiskScore = w_mitre * mitre_risk
            + w_severity * max_event_severity
            + w_ml * ml_confidence
            + w_graph * graph_complexity

Levels:
  - Critical (90-100)
  - High (70-89)
  - Medium (40-69)
  - Low (0-39)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from secureshield.forensics.schema import CorrelatedIncident, Severity
from secureshield.common.logging_utils import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Map severity string to numeric weight
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.8,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.2,
    Severity.UNKNOWN: 0.1,
}

# Tactic weights (closer to impact = higher risk)
TACTIC_WEIGHTS = {
    "Execution": 0.6,
    "Persistence": 0.7,
    "Privilege Escalation": 0.8,
    "Defense Evasion": 0.7,
    "Credential Access": 0.8,
    "Discovery": 0.4,
    "Lateral Movement": 0.9,
    "Collection": 0.6,
    "Command and Control": 0.8,
    "Exfiltration": 0.9,
    "Impact": 1.0,
}


class RiskAssessor:
    """
    Computes a standardized risk score and risk level for a CorrelatedIncident.
    """

    def __init__(
        self,
        weight_mitre: float = 0.35,
        weight_severity: float = 0.35,
        weight_ml: float = 0.20,
        weight_graph: float = 0.10,
    ):
        # Normalize weights just in case
        total = weight_mitre + weight_severity + weight_ml + weight_graph
        self.w_mitre = weight_mitre / total
        self.w_severity = weight_severity / total
        self.w_ml = weight_ml / total
        self.w_graph = weight_graph / total

    def _assess_mitre_risk(self, incident: CorrelatedIncident) -> float:
        """Score based on highest-weight mapped MITRE tactic."""
        if not incident.att_ck_mappings:
            return 0.0

        max_tactic_weight = 0.0
        for mapping in incident.att_ck_mappings:
            tactics = [t.strip() for t in mapping.get("tactic", "").split("/")]
            for tactic in tactics:
                max_tactic_weight = max(max_tactic_weight, TACTIC_WEIGHTS.get(tactic, 0.5))

        return max_tactic_weight

    def _assess_severity_risk(self, incident: CorrelatedIncident) -> float:
        """Score based on the highest severity event in the incident."""
        if not incident.events:
            return 0.0

        max_sev = 0.0
        for event in incident.events:
            max_sev = max(max_sev, SEVERITY_WEIGHTS.get(event.severity, 0.1))
        return max_sev

    def _assess_ml_risk(self, incident: CorrelatedIncident) -> float:
        """Score based on maximum ML confidence (if available)."""
        ml_confidences = [
            e.ml_confidence for e in incident.events
            if e.ml_confidence is not None
        ]
        return max(ml_confidences) if ml_confidences else 0.0

    def _assess_graph_risk(self, incident: CorrelatedIncident) -> float:
        """
        Score based on graph complexity.
        More events (longer chain) generally imply a more entrenched attack.
        """
        n_events = len(incident.events)
        # Cap at 10 events for max graph complexity score
        return min(1.0, n_events / 10.0)

    def assess(self, incident: CorrelatedIncident) -> Dict[str, Any]:
        """
        Assess risk for a single incident.

        Updates the incident object directly and returns a risk summary dict.
        """
        r_mitre = self._assess_mitre_risk(incident)
        r_sev = self._assess_severity_risk(incident)
        r_ml = self._assess_ml_risk(incident)
        r_graph = self._assess_graph_risk(incident)

        raw_score = (
            self.w_mitre * r_mitre
            + self.w_severity * r_sev
            + self.w_ml * r_ml
            + self.w_graph * r_graph
        )

        risk_score = round(raw_score * 100, 1)

        # Level determination
        if risk_score >= 90:
            level = "CRITICAL"
        elif risk_score >= 70:
            level = "HIGH"
        elif risk_score >= 40:
            level = "MEDIUM"
        else:
            level = "LOW"

        # Risk factors (explainability of the risk score)
        factors = []
        if r_mitre > 0.7:
            factors.append("High-impact MITRE ATT&CK tactics identified.")
        if r_sev >= 0.8:
            factors.append("Contains HIGH or CRITICAL severity forensic events.")
        if r_ml > 0.8:
            factors.append("High confidence ML malware detection.")
        if len(incident.events) >= 5:
            factors.append("Complex multi-step attack chain.")

        # Update incident
        incident.risk_score = risk_score
        incident.risk_level = level
        incident.risk_factors = factors

        logger.info(
            f"Assessed Risk for {incident.incident_id}: "
            f"Score={risk_score}/100, Level={level}"
        )

        return {
            "risk_score": risk_score,
            "risk_level": level,
            "risk_factors": factors,
            "components": {
                "mitre_component": round(r_mitre, 3),
                "severity_component": round(r_sev, 3),
                "ml_component": round(r_ml, 3),
                "graph_component": round(r_graph, 3),
            },
        }
