"""
secureshield.forensics.schema
==============================
Normalized forensic event schema using Pydantic.

Every forensic event in SecureShield is represented as a ForensicEvent.
Different evidence sources (ML predictions, memory forensics features,
synthetic events derived from Volatility statistics) are normalized
into this common schema before entering the correlation engine.

IMPORTANT — SYNTHETIC EVENT DISCLAIMER:
  When CIC-MalMem-2022 ML features are mapped to forensic event types,
  those events are SYNTHETIC — they are derived from aggregate Volatility
  statistics, NOT from real endpoint telemetry logs.
  All synthetic events are clearly labeled with:
    source_type = "SYNTHETIC_FROM_ML_FEATURES"
  This must NEVER be conflated with real forensic evidence in publications.

Event categories supported:
  - process_creation / process_termination / process_injection
  - parent_child_relationship
  - file_creation / file_modification / file_execution
  - memory_commit / dll_hiding
  - network_connection / dns_query
  - service_creation / service_manipulation
  - registry_modification
  - kernel_callback / process_hiding
  - ml_detection (ML model output as evidence)
  - desktop_access / user_activity
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from enum import Enum

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class EventType(str, Enum):
    """Supported forensic event types."""
    # Process events
    PROCESS_CREATION = "process_creation"
    PROCESS_TERMINATION = "process_termination"
    PROCESS_INJECTION = "process_injection"
    PROCESS_HIDING = "process_hiding"
    PARENT_CHILD = "parent_child_relationship"

    # Memory events
    MEMORY_COMMIT = "memory_commit"
    DLL_HIDING = "dll_hiding"

    # File events
    FILE_CREATION = "file_creation"
    FILE_MODIFICATION = "file_modification"
    FILE_EXECUTION = "file_execution"

    # Network events
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"

    # Service/Registry events
    SERVICE_CREATION = "service_creation"
    SERVICE_MANIPULATION = "service_manipulation"
    REGISTRY_MODIFICATION = "registry_modification"
    KERNEL_CALLBACK = "kernel_callback"

    # Desktop/User events
    DESKTOP_ACCESS = "desktop_access"
    USER_ACTIVITY = "user_activity"

    # ML-derived evidence
    ML_DETECTION = "ml_detection"

    # Generic/Unknown
    UNKNOWN = "unknown"


class SourceType(str, Enum):
    """Origin of the forensic event."""
    # Real evidence sources
    VOLATILITY_MEMORY_DUMP = "volatility_memory_dump"
    SYSMON_LOG = "sysmon_log"
    WINDOWS_EVENT_LOG = "windows_event_log"
    EDR_TELEMETRY = "edr_telemetry"
    NETWORK_PCAP = "network_pcap"
    FILE_SYSTEM_AUDIT = "file_system_audit"

    # Synthetic sources — clearly labeled
    SYNTHETIC_FROM_ML_FEATURES = "SYNTHETIC_FROM_ML_FEATURES"
    ML_MODEL_OUTPUT = "ml_model_output"

    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Event severity level."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Forensic Event Model
# ---------------------------------------------------------------------------

class ForensicEvent(BaseModel):
    """
    Normalized forensic event representation.

    All fields are optional except event_id, timestamp, event_type, and source_type.
    Missing fields should remain None rather than being fabricated.

    When source_type is SYNTHETIC_FROM_ML_FEATURES, the event is derived
    from aggregate Volatility statistics and NOT from real endpoint telemetry.
    """

    # ── Core identifiers ──────────────────────────────────────────────────
    event_id: str = Field(
        default_factory=lambda: f"EVT-{uuid.uuid4().hex[:8].upper()}"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    event_type: EventType = EventType.UNKNOWN
    source_type: SourceType = SourceType.UNKNOWN
    severity: Severity = Severity.UNKNOWN

    # ── Host and session context ──────────────────────────────────────────
    host: Optional[str] = None
    user: Optional[str] = None
    session_id: Optional[str] = None

    # ── Process information ───────────────────────────────────────────────
    process: Optional[str] = None
    process_path: Optional[str] = None
    pid: Optional[int] = None
    parent_process: Optional[str] = None
    ppid: Optional[int] = None
    command_line: Optional[str] = None

    # ── File information ──────────────────────────────────────────────────
    file: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None  # MD5/SHA256
    file_size_bytes: Optional[int] = None

    # ── Network information ───────────────────────────────────────────────
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    domain: Optional[str] = None

    # ── Memory forensics (Volatility-specific) ────────────────────────────
    n_injections: Optional[int] = None
    commit_charge: Optional[float] = None
    n_handles: Optional[int] = None
    n_modules: Optional[int] = None
    n_services: Optional[int] = None

    # ── ML evidence ──────────────────────────────────────────────────────
    ml_prediction: Optional[str] = None       # "malicious" | "benign"
    ml_confidence: Optional[float] = None     # [0.0, 1.0]
    ml_model: Optional[str] = None
    ml_top_features: Optional[List[Dict[str, Any]]] = None

    # ── Correlation metadata ──────────────────────────────────────────────
    evidence_id: Optional[str] = None         # links to raw evidence artifact
    incident_id: Optional[str] = None         # set by correlation engine
    correlation_score: Optional[float] = None

    # ── Confidence and context ────────────────────────────────────────────
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    synthetic: bool = False                   # True if derived from ML features
    raw_feature_values: Optional[Dict[str, float]] = None  # original feature values

    # ── Free-form metadata ────────────────────────────────────────────────
    metadata: Optional[Dict[str, Any]] = None
    notes: Optional[str] = None

    @model_validator(mode="after")
    def flag_synthetic_events(self) -> "ForensicEvent":
        """Auto-flag events from synthetic sources."""
        if self.source_type == SourceType.SYNTHETIC_FROM_ML_FEATURES:
            object.__setattr__(self, "synthetic", True)
            if self.notes is None:
                object.__setattr__(
                    self, "notes",
                    "SYNTHETIC EVENT: Derived from aggregate Volatility ML features. "
                    "NOT real endpoint telemetry. Do not conflate with real forensic evidence."
                )
        return self

    @field_validator("ml_confidence")
    @classmethod
    def validate_confidence_range(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and not (0.0 <= v <= 1.0):
            raise ValueError(f"ml_confidence must be in [0, 1], got {v}")
        return v

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict with datetime as ISO string."""
        d = self.model_dump()
        d["timestamp"] = self.timestamp.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ForensicEvent":
        """Deserialize from dict."""
        return cls(**data)

    def __repr__(self) -> str:
        return (
            f"ForensicEvent({self.event_id}, {self.event_type.value}, "
            f"t={self.timestamp.isoformat()[:19]}, "
            f"synthetic={self.synthetic})"
        )


# ---------------------------------------------------------------------------
# Incident model
# ---------------------------------------------------------------------------

class CorrelatedIncident(BaseModel):
    """
    A correlated incident — a group of ForensicEvents linked by the
    correlation engine as belonging to the same attack activity.
    """

    incident_id: str = Field(
        default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # Event chain
    events: List[ForensicEvent] = Field(default_factory=list)
    correlation_score: float = Field(default=0.0, ge=0.0, le=1.0)

    # Risk assessment (populated by risk module)
    risk_score: Optional[float] = None        # [0, 100]
    risk_level: Optional[str] = None          # Low/Medium/High/Critical
    risk_factors: Optional[List[str]] = None

    # MITRE ATT&CK mappings (populated by mitre module)
    att_ck_mappings: Optional[List[Dict[str, Any]]] = None

    # Timeline (populated by timeline module)
    timeline: Optional[List[Dict[str, Any]]] = None

    # Response recommendations
    recommendations: Optional[List[Dict[str, Any]]] = None

    # Metadata
    host: Optional[str] = None
    contains_synthetic_events: bool = False
    notes: Optional[str] = None

    def add_event(self, event: ForensicEvent) -> None:
        """Add a forensic event and update synthetic flag."""
        self.events.append(event)
        if event.synthetic:
            self.contains_synthetic_events = True

    def to_dict(self) -> Dict[str, Any]:
        """Full serialization."""
        return {
            "incident_id": self.incident_id,
            "created_at": self.created_at.isoformat(),
            "n_events": len(self.events),
            "events": [e.to_dict() for e in self.events],
            "correlation_score": self.correlation_score,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "risk_factors": self.risk_factors,
            "att_ck_mappings": self.att_ck_mappings,
            "timeline": self.timeline,
            "recommendations": self.recommendations,
            "host": self.host,
            "contains_synthetic_events": self.contains_synthetic_events,
            "notes": self.notes,
        }
