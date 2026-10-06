"""
secureshield.response.playbooks
================================
Automated response recommendations and playbooks.

Maps identified risks and MITRE ATT&CK techniques to actionable response
steps for security analysts.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from secureshield.forensics.schema import CorrelatedIncident, EventType
from secureshield.common.logging_utils import get_logger

logger = get_logger(__name__)


class ResponseRecommender:
    """
    Generates response playbooks and recommendations based on incident context.
    """

    def __init__(self):
        pass

    def recommend(self, incident: CorrelatedIncident) -> List[Dict[str, Any]]:
        """
        Generate recommendations for a CorrelatedIncident.
        Populates the incident.recommendations field.
        """
        recs = []

        # 1. Base response based on Risk Level
        if incident.risk_level in ["CRITICAL", "HIGH"]:
            recs.append({
                "action": "Isolate Host",
                "description": (
                    f"Immediately isolate host {incident.host or '(unknown)'} "
                    "from the network to prevent lateral movement and C2."
                ),
                "priority": "P1",
                "automated": False,
            })
            recs.append({
                "action": "Acquire Memory Dump",
                "description": "Capture full volatile memory (RAM) for deep forensic analysis.",
                "priority": "P1",
                "automated": False,
            })

        # 2. Check for Process Injection / Hollowing
        has_injection = any(
            t in ["T1055", "T1055.012"]
            for m in (incident.att_ck_mappings or [])
            for t in [m.get("technique_id"), m.get("sub_technique")]
            if t
        )
        if has_injection:
            recs.append({
                "action": "Analyze Process Memory",
                "description": "Dump and analyze memory of suspicious processes for injected PE files or shellcode.",
                "priority": "P2",
                "automated": False,
            })

        # 3. Check for Network C2
        has_c2 = any(
            m.get("tactic") == "Command and Control"
            for m in (incident.att_ck_mappings or [])
        )
        if has_c2:
            recs.append({
                "action": "Block C2 Indicators",
                "description": "Block identified destination IPs/Domains at the perimeter firewall/proxy.",
                "priority": "P1",
                "automated": True,
            })

        # 4. Check for Persistence (Services)
        has_service_persistence = any(
            e.event_type in [EventType.SERVICE_CREATION, EventType.SERVICE_MANIPULATION]
            for e in incident.events
        )
        if has_service_persistence:
            recs.append({
                "action": "Review Windows Services",
                "description": "Audit recently created or modified Windows services for persistence mechanisms.",
                "priority": "P2",
                "automated": False,
            })

        # 5. Check for Rootkit/Hiding
        has_rootkit = any(
            t == "T1014"
            for m in (incident.att_ck_mappings or [])
            for t in [m.get("technique_id")]
        )
        if has_rootkit:
            recs.append({
                "action": "Offline Scanning",
                "description": "Host exhibits rootkit behavior (API hooking/hiding). Consider offline scanning or rebuilding.",
                "priority": "P1",
                "automated": False,
            })

        # Default fallback
        if not recs:
            recs.append({
                "action": "Monitor Host",
                "description": "Increase monitoring telemetry for this host. Review event logs for anomalies.",
                "priority": "P3",
                "automated": True,
            })

        incident.recommendations = recs
        logger.info(f"Generated {len(recs)} response recommendations for incident {incident.incident_id}")
        return recs
