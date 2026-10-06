"""
secureshield.forensics.normalizer
===================================
Event normalization — converts raw evidence into ForensicEvent objects.

For CIC-MalMem-2022, evidence arrives as:
  1. ML prediction dicts (model output + SHAP explanation)
  2. Raw Volatility feature rows (memory forensics statistics)

CRITICAL DISCLAIMER:
  CIC-MalMem-2022 provides AGGREGATE Volatility statistics per process dump.
  It does NOT provide individual timestamped endpoint telemetry.
  Events generated from this dataset are SYNTHETIC approximations.
  They are labeled with source_type = SYNTHETIC_FROM_ML_FEATURES.
  This is a known limitation documented in LIMITATIONS.md.

The normalizer accepts dictionaries and returns validated ForensicEvent objects.
Invalid/incomplete fields gracefully default to None.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import numpy as np

from secureshield.forensics.schema import (
    CorrelatedIncident,
    EventType,
    ForensicEvent,
    Severity,
    SourceType,
)
from secureshield.common.logging_utils import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Feature → event type mapping for CIC-MalMem-2022
# ---------------------------------------------------------------------------

FEATURE_EVENT_MAP: Dict[str, EventType] = {
    "malfind.ninjections": EventType.PROCESS_INJECTION,
    "malfind.uniqueInjections": EventType.PROCESS_INJECTION,
    "malfind.commitCharge": EventType.MEMORY_COMMIT,
    "malfind.protection": EventType.MEMORY_COMMIT,
    "ldrmodules.not_in_load": EventType.DLL_HIDING,
    "ldrmodules.not_in_init": EventType.DLL_HIDING,
    "ldrmodules.not_in_mem": EventType.DLL_HIDING,
    "ldrmodules.not_in_load_avg": EventType.DLL_HIDING,
    "ldrmodules.not_in_init_avg": EventType.DLL_HIDING,
    "ldrmodules.not_in_mem_avg": EventType.DLL_HIDING,
    "pslist.nppid": EventType.PARENT_CHILD,
    "pslist.nproc": EventType.PROCESS_CREATION,
    "pslist.avg_threads": EventType.PROCESS_CREATION,
    "pslist.avg_handlers": EventType.PROCESS_CREATION,
    "psxview.not_in_pslist": EventType.PROCESS_HIDING,
    "psxview.not_in_eprocess_pool": EventType.PROCESS_HIDING,
    "psxview.not_in_ethread_pool": EventType.PROCESS_HIDING,
    "handles.ndesktop": EventType.DESKTOP_ACCESS,
    "svcscan.nservices": EventType.SERVICE_CREATION,
    "svcscan.nactive": EventType.SERVICE_MANIPULATION,
    "svcscan.kernel_drivers": EventType.KERNEL_CALLBACK,
    "callbacks.ncallbacks": EventType.KERNEL_CALLBACK,
    "callbacks.nanonymous": EventType.KERNEL_CALLBACK,
}

# Map feature values to severity based on research thresholds
def _feature_to_severity(feature: str, value: float) -> Severity:
    """Heuristic severity assignment based on feature values."""
    if feature == "malfind.ninjections" and value > 0:
        return Severity.HIGH if value > 2 else Severity.MEDIUM
    if feature == "ldrmodules.not_in_load" and value > 0:
        return Severity.MEDIUM
    if feature == "psxview.not_in_pslist" and value > 0:
        return Severity.CRITICAL
    if feature == "callbacks.ncallbacks" and value > 5:
        return Severity.HIGH
    return Severity.LOW


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

class EventNormalizer:
    """
    Normalizes raw evidence sources into ForensicEvent objects.

    All events from CIC-MalMem-2022 are SYNTHETIC — they are derived from
    aggregate Volatility statistics, not real endpoint telemetry.
    """

    def __init__(self, base_timestamp: Optional[datetime] = None):
        self.base_timestamp = base_timestamp or datetime.now(timezone.utc)

    def normalize_ml_prediction(
        self,
        prediction: str,
        confidence: float,
        model_name: str,
        top_features: List[Dict[str, Any]],
        host: Optional[str] = None,
        evidence_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> ForensicEvent:
        """
        Create a ForensicEvent from an ML model prediction.

        This represents the ML detection result as evidence.
        """
        return ForensicEvent(
            timestamp=timestamp or self.base_timestamp,
            event_type=EventType.ML_DETECTION,
            source_type=SourceType.ML_MODEL_OUTPUT,
            severity=Severity.HIGH if prediction == "malicious" and confidence > 0.8
                     else (Severity.MEDIUM if prediction == "malicious" else Severity.LOW),
            host=host,
            ml_prediction=prediction,
            ml_confidence=round(confidence, 4),
            ml_model=model_name,
            ml_top_features=top_features,
            evidence_id=evidence_id,
            confidence=confidence,
            synthetic=False,  # ML prediction itself is not synthetic
        )

    def normalize_volatility_row(
        self,
        feature_values: Dict[str, float],
        row_index: int,
        label: Optional[int] = None,
        host: Optional[str] = None,
        base_time: Optional[datetime] = None,
    ) -> List[ForensicEvent]:
        """
        Convert a single CIC-MalMem-2022 feature row into synthetic ForensicEvents.

        Each non-zero significant feature generates a synthetic event.
        Events are time-offset to simulate a realistic sequence.

        IMPORTANT: These events are SYNTHETIC. They are derived from aggregate
        Volatility statistics, not from real endpoint telemetry.

        Args:
            feature_values: Dict of feature_name → float value.
            row_index: Dataset row index (for reproducibility).
            label: Ground truth label (0=Benign, 1=Malware).
            host: Simulated hostname.
            base_time: Base timestamp for this row.

        Returns:
            List of synthetic ForensicEvents.
        """
        events = []
        t = base_time or self.base_timestamp
        offset_secs = 0

        for feature, event_type in FEATURE_EVENT_MAP.items():
            value = feature_values.get(feature, 0.0)
            if value is None or (isinstance(value, float) and np.isnan(value)):
                value = 0.0

            # Only emit events for non-zero features (heuristic threshold)
            if value <= 0:
                continue

            severity = _feature_to_severity(feature, value)
            t_event = t + timedelta(seconds=offset_secs)
            offset_secs += 1  # synthetic 1-second spacing

            # Build event metadata
            metadata = {
                "feature_name": feature,
                "feature_value": float(value),
                "row_index": row_index,
                "ground_truth_label": "malware" if label == 1 else "benign" if label == 0 else None,
                "synthetic_note": (
                    "Generated from CIC-MalMem-2022 aggregate Volatility statistic. "
                    "NOT real endpoint telemetry."
                ),
            }

            event = ForensicEvent(
                timestamp=t_event,
                event_type=event_type,
                source_type=SourceType.SYNTHETIC_FROM_ML_FEATURES,
                severity=severity,
                host=host or f"host-{row_index % 100:03d}",
                evidence_id=f"CIC-ROW-{row_index:06d}",
                confidence=min(1.0, value / 10.0) if value <= 10 else 1.0,
                synthetic=True,
                raw_feature_values={feature: float(value)},
                metadata=metadata,
                notes=(
                    f"SYNTHETIC: Derived from Volatility feature '{feature}' = {value:.2f}. "
                    "See LIMITATIONS.md for details."
                ),
            )

            # Add feature-specific fields
            if event_type in (EventType.PROCESS_INJECTION, EventType.PROCESS_CREATION,
                              EventType.PARENT_CHILD, EventType.PROCESS_HIDING):
                event = event.model_copy(update={"n_injections": int(value) if feature == "malfind.ninjections" else None})

            if event_type == EventType.MEMORY_COMMIT:
                event = event.model_copy(update={"commit_charge": float(value)})

            if event_type in (EventType.SERVICE_CREATION, EventType.SERVICE_MANIPULATION):
                event = event.model_copy(update={"n_services": int(value)})

            events.append(event)

        logger.debug(f"Row {row_index}: generated {len(events)} synthetic events")
        return events

    def normalize_raw_dict(self, raw: Dict[str, Any]) -> Optional[ForensicEvent]:
        """
        Normalize a generic raw event dict into a ForensicEvent.
        Gracefully handles missing fields.

        Args:
            raw: Dict with any subset of ForensicEvent fields.

        Returns:
            Validated ForensicEvent or None if required fields are missing.
        """
        try:
            return ForensicEvent(**raw)
        except Exception as e:
            logger.warning(f"Event normalization failed: {e}. Raw: {raw}")
            # Attempt minimal event
            try:
                return ForensicEvent(
                    event_type=raw.get("event_type", EventType.UNKNOWN),
                    source_type=raw.get("source_type", SourceType.UNKNOWN),
                    metadata=raw,
                    notes=f"Normalization error: {e}",
                )
            except Exception:
                return None
