"""
secureshield.timeline.reconstructor
=====================================
Chronological attack timeline reconstruction from correlated incidents.

Produces a structured timeline linking each event to its evidence ID,
suitable for forensic reporting and publication.

Timeline output format:
  [
    {
      "timestamp": "2024-01-15T09:42:01Z",
      "event_id": "EVT-ABCD1234",
      "event_type": "process_creation",
      "description": "Process started: suspicious.exe (PID 4521)",
      "evidence_id": "CIC-ROW-001234",
      "severity": "high",
      "synthetic": true,
      "confidence": 0.91
    },
    ...
  ]
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from secureshield.forensics.schema import CorrelatedIncident, EventType, ForensicEvent
from secureshield.common.logging_utils import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Event description generator
# ---------------------------------------------------------------------------

def describe_event(event: ForensicEvent) -> str:
    """Generate a human-readable description of a forensic event."""
    t = event.event_type

    if t == EventType.PROCESS_CREATION:
        proc = event.process or "unknown"
        pid = f"(PID {event.pid})" if event.pid else ""
        parent = f"← {event.parent_process}" if event.parent_process else ""
        return f"Process started: {proc} {pid} {parent}".strip()

    elif t == EventType.PROCESS_INJECTION:
        n = int(event.n_injections or 0)
        return (
            f"Memory injection detected: {n} injection(s) observed "
            f"(commit charge: {event.commit_charge or 'unknown'})"
        )

    elif t == EventType.MEMORY_COMMIT:
        return f"Suspicious memory commit: charge={event.commit_charge or 'unknown'}"

    elif t == EventType.DLL_HIDING:
        feature = list(event.raw_feature_values.keys())[0] if event.raw_feature_values else "unknown"
        val = list(event.raw_feature_values.values())[0] if event.raw_feature_values else 0
        return f"DLL hiding indicator: {feature}={val:.1f} (modules not in expected lists)"

    elif t == EventType.NETWORK_CONNECTION:
        dst = f"{event.dst_ip}:{event.dst_port}" if event.dst_port else event.dst_ip or "unknown"
        proto = event.protocol or "TCP"
        return f"Network connection established: {proto} → {dst}"

    elif t == EventType.DNS_QUERY:
        return f"DNS query: {event.domain or 'unknown'} → {event.dst_ip or 'unresolved'}"

    elif t == EventType.FILE_CREATION:
        return f"File created: {event.file_path or event.file or 'unknown'}"

    elif t == EventType.FILE_MODIFICATION:
        return f"File modified: {event.file_path or event.file or 'unknown'}"

    elif t == EventType.FILE_EXECUTION:
        return f"File executed: {event.file_path or event.file or 'unknown'}"

    elif t == EventType.SERVICE_CREATION:
        n = event.n_services or 0
        return f"Service creation/registration: {n} services in memory"

    elif t == EventType.SERVICE_MANIPULATION:
        return f"Service manipulation: {event.n_services or 'unknown'} active services"

    elif t == EventType.KERNEL_CALLBACK:
        return "Kernel callback registration detected (rootkit indicator)"

    elif t == EventType.PROCESS_HIDING:
        return "Process hiding detected: process not visible in standard process list (psxview anomaly)"

    elif t == EventType.PARENT_CHILD:
        proc = event.process or "unknown"
        parent = event.parent_process or "unknown"
        return f"Process chain: {parent} → {proc}"

    elif t == EventType.ML_DETECTION:
        pred = event.ml_prediction or "unknown"
        conf = f"{event.ml_confidence:.1%}" if event.ml_confidence else "unknown"
        model = event.ml_model or "ML model"
        return f"ML classification: {pred.upper()} (confidence: {conf}) by {model}"

    elif t == EventType.DESKTOP_ACCESS:
        return "Desktop object access detected (potential screen capture or UI hijack)"

    elif t == EventType.USER_ACTIVITY:
        return f"User activity: {event.user or 'unknown'}"

    else:
        return f"Event: {t.value}"


# ---------------------------------------------------------------------------
# Timeline Reconstructor
# ---------------------------------------------------------------------------

class TimelineReconstructor:
    """
    Reconstructs a chronological attack timeline from a CorrelatedIncident.
    """

    def reconstruct(self, incident: CorrelatedIncident) -> List[Dict[str, Any]]:
        """
        Build the chronological timeline for an incident.

        Each entry links back to its evidence ID for auditability.

        Args:
            incident: CorrelatedIncident with sorted events.

        Returns:
            List of timeline entries sorted by timestamp.
        """
        if not incident.events:
            return []

        sorted_events = sorted(incident.events, key=lambda e: e.timestamp)
        timeline = []

        for i, event in enumerate(sorted_events):
            entry = {
                "step": i + 1,
                "timestamp": event.timestamp.isoformat(),
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "description": describe_event(event),
                "evidence_id": event.evidence_id,
                "severity": event.severity.value,
                "confidence": round(event.confidence, 4),
                "host": event.host,
                "synthetic": event.synthetic,
            }

            # Add process context if available
            if event.process or event.pid:
                entry["process_context"] = {
                    "process": event.process,
                    "pid": event.pid,
                    "parent": event.parent_process,
                    "ppid": event.ppid,
                }

            # Add network context if available
            if event.dst_ip or event.domain:
                entry["network_context"] = {
                    "dst_ip": event.dst_ip,
                    "dst_port": event.dst_port,
                    "domain": event.domain,
                    "protocol": event.protocol,
                }

            # Add ML context if applicable
            if event.event_type == EventType.ML_DETECTION:
                entry["ml_context"] = {
                    "prediction": event.ml_prediction,
                    "confidence": event.ml_confidence,
                    "model": event.ml_model,
                    "top_features": event.ml_top_features,
                }

            if event.synthetic:
                entry["synthetic_note"] = (
                    "SYNTHETIC: Derived from aggregate Volatility ML features. "
                    "NOT real endpoint telemetry."
                )

            timeline.append(entry)

        return timeline

    def format_text_timeline(self, timeline: List[Dict[str, Any]]) -> str:
        """Format timeline as human-readable text for reports."""
        lines = ["=" * 70, "ATTACK TIMELINE", "=" * 70, ""]

        for entry in timeline:
            ts = entry["timestamp"][:19].replace("T", " ")
            step = f"Step {entry['step']:02d}"
            sev = entry["severity"].upper()
            syn = " [SYNTHETIC]" if entry.get("synthetic") else ""
            eid = entry.get("evidence_id", "N/A")

            lines.append(f"{ts}  {step}  [{sev}]{syn}")
            lines.append(f"  {entry['description']}")
            lines.append(f"  Event ID: {entry['event_id']} | Evidence: {eid}")
            if entry.get("synthetic_note"):
                lines.append(f"  ⚠ {entry['synthetic_note']}")
            lines.append("")

        return "\n".join(lines)

    def save(
        self,
        timeline: List[Dict[str, Any]],
        incident: CorrelatedIncident,
        output_dir: str | Path,
    ) -> None:
        """Save timeline to JSON and text formats."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # JSON
        json_path = output_dir / f"timeline_{incident.incident_id}.json"
        with open(json_path, "w") as f:
            json.dump(
                {
                    "incident_id": incident.incident_id,
                    "n_events": len(timeline),
                    "correlation_score": incident.correlation_score,
                    "contains_synthetic": incident.contains_synthetic_events,
                    "timeline": timeline,
                },
                f, indent=2,
            )
        logger.info(f"Timeline saved: {json_path}")

        # Text report
        txt_path = output_dir / f"timeline_{incident.incident_id}.txt"
        with open(txt_path, "w") as f:
            f.write(self.format_text_timeline(timeline))
        logger.info(f"Text timeline saved: {txt_path}")
