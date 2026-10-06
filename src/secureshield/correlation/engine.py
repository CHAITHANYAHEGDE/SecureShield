"""
secureshield.correlation.engine
=================================
Multi-dimensional event correlation engine.

Implements the core SecureShield research contribution:
correlating ML predictions with forensic evidence across multiple
signal dimensions to produce richer, higher-confidence incident assessments.

Correlation Score Formula:
  CorrelationScore =
      w1 * temporal_similarity
    + w2 * process_relationship
    + w3 * file_relationship
    + w4 * network_relationship
    + w5 * evidence_confidence
    + w6 * ml_confidence

IMPORTANT DISCLAIMER:
  Correlation weights are HEURISTIC by default.
  They have NOT been experimentally optimized unless ablation study
  results are used to tune them. The ablation study (Section 17 of the
  research spec) evaluates the contribution of each signal dimension.
  Do not claim these weights are scientifically optimal in the paper
  unless ablation results support that claim.

Signal descriptions:
  - Temporal: Events within configurable time window get higher scores
  - Process: Events sharing process name, PID, or parent-child relationships
  - File: Events sharing file path, hash, or file-related activity chains
  - Network: Events sharing source/destination IP, port, or domain
  - Evidence confidence: Average confidence of constituent events
  - ML confidence: Confidence of the ML malware prediction (if present)
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx
import numpy as np

from secureshield.forensics.schema import CorrelatedIncident, EventType, ForensicEvent
from secureshield.common.config import CorrelationWeights
from secureshield.common.logging_utils import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Similarity functions for each signal dimension
# ---------------------------------------------------------------------------

def temporal_similarity(e1: ForensicEvent, e2: ForensicEvent, window_sec: int = 30) -> float:
    """
    Temporal similarity: 1.0 if events are simultaneous, decaying with time.
    Uses exponential decay: exp(-|delta_t| / window).
    """
    if e1.timestamp is None or e2.timestamp is None:
        return 0.0
    delta = abs((e1.timestamp - e2.timestamp).total_seconds())
    if delta > window_sec * 3:
        return 0.0
    return math.exp(-delta / window_sec)


def process_relationship_score(e1: ForensicEvent, e2: ForensicEvent) -> float:
    """
    Process relationship: events sharing process, PID, or parent-child link.
    Returns [0, 1] based on number of matching process attributes.
    """
    score = 0.0
    matches = 0
    checks = 0

    # PID match (strongest signal)
    if e1.pid is not None and e2.pid is not None:
        checks += 1
        if e1.pid == e2.pid:
            matches += 2  # weighted higher
        checks += 1

    # Parent-child relationship
    if e1.ppid is not None and e2.pid is not None:
        checks += 1
        if e1.ppid == e2.pid:
            matches += 1

    # Process name match
    if e1.process is not None and e2.process is not None:
        checks += 1
        if e1.process.lower() == e2.process.lower():
            matches += 1

    # Parent process name match
    if e1.parent_process is not None and e2.process is not None:
        checks += 1
        if e1.parent_process.lower() == e2.process.lower():
            matches += 1

    if checks == 0:
        return 0.0
    return min(1.0, matches / max(checks, 1))


def file_relationship_score(e1: ForensicEvent, e2: ForensicEvent) -> float:
    """
    File relationship: shared file path, hash, or file event chain.
    """
    score = 0.0

    # Hash match (strongest)
    if (e1.file_hash is not None and e2.file_hash is not None
            and e1.file_hash == e2.file_hash):
        score += 0.6

    # File path match
    if e1.file_path is not None and e2.file_path is not None:
        if e1.file_path == e2.file_path:
            score += 0.3
        elif e1.file_path and e2.file_path and (
            e1.file_path in e2.file_path or e2.file_path in e1.file_path
        ):
            score += 0.1

    # File name match
    if e1.file is not None and e2.file is not None:
        if e1.file == e2.file:
            score += 0.1

    # Both are file-related events (creation → modification → execution chain)
    file_types = {EventType.FILE_CREATION, EventType.FILE_MODIFICATION, EventType.FILE_EXECUTION}
    if e1.event_type in file_types and e2.event_type in file_types:
        score += 0.1

    return min(1.0, score)


def network_relationship_score(e1: ForensicEvent, e2: ForensicEvent) -> float:
    """
    Network relationship: shared IP, port, domain, or protocol.
    """
    score = 0.0

    # Same destination IP (common C2 pattern)
    if e1.dst_ip is not None and e2.dst_ip is not None and e1.dst_ip == e2.dst_ip:
        score += 0.4

    # Same source IP
    if e1.src_ip is not None and e2.src_ip is not None and e1.src_ip == e2.src_ip:
        score += 0.2

    # Same destination port
    if e1.dst_port is not None and e2.dst_port is not None and e1.dst_port == e2.dst_port:
        score += 0.1

    # Same domain
    if e1.domain is not None and e2.domain is not None and e1.domain == e2.domain:
        score += 0.3

    # Both are network events
    net_types = {EventType.NETWORK_CONNECTION, EventType.DNS_QUERY}
    if e1.event_type in net_types and e2.event_type in net_types:
        score += 0.1

    return min(1.0, score)


def evidence_confidence_score(e1: ForensicEvent, e2: ForensicEvent) -> float:
    """Average confidence of the two events."""
    return (e1.confidence + e2.confidence) / 2.0


def ml_confidence_score(events: List[ForensicEvent]) -> float:
    """
    ML confidence signal: average ML confidence across all ML detection events.
    Returns 0 if no ML events present.
    """
    ml_events = [e for e in events if e.event_type == EventType.ML_DETECTION
                 and e.ml_confidence is not None]
    if not ml_events:
        return 0.0
    return float(np.mean([e.ml_confidence for e in ml_events]))


# ---------------------------------------------------------------------------
# Pairwise correlation score
# ---------------------------------------------------------------------------

def pairwise_correlation_score(
    e1: ForensicEvent,
    e2: ForensicEvent,
    weights: CorrelationWeights,
    temporal_window: int = 30,
) -> float:
    """
    Compute the multi-dimensional correlation score between two events.

    Args:
        e1, e2: Events to compare.
        weights: Configurable correlation weights (HEURISTIC by default).
        temporal_window: Time window in seconds for temporal similarity.

    Returns:
        Correlation score in [0, 1].
    """
    temp = temporal_similarity(e1, e2, temporal_window)
    proc = process_relationship_score(e1, e2)
    file_ = file_relationship_score(e1, e2)
    net = network_relationship_score(e1, e2)
    evid = evidence_confidence_score(e1, e2)

    # ML confidence applies to both events if either is an ML detection
    ml_conf = max(
        e1.ml_confidence or 0.0,
        e2.ml_confidence or 0.0,
    )

    score = (
        weights.temporal * temp
        + weights.process_relationship * proc
        + weights.file_relationship * file_
        + weights.network_relationship * net
        + weights.evidence_confidence * evid
        + weights.ml_confidence * ml_conf
    )
    return round(min(1.0, score), 4)


# ---------------------------------------------------------------------------
# Correlation Engine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """
    Multi-dimensional event correlation engine.

    Given a list of ForensicEvents, clusters them into CorrelatedIncidents
    using pairwise correlation scores and graph-based community detection.

    Does NOT simply group all events within a time window — multiple signals
    are required to form a high-confidence incident cluster.
    """

    def __init__(
        self,
        weights: Optional[CorrelationWeights] = None,
        temporal_window_sec: int = 30,
        min_correlation_score: float = 0.30,
        max_events_per_incident: int = 50,
    ):
        self.weights = weights or CorrelationWeights()
        self.temporal_window_sec = temporal_window_sec
        self.min_correlation_score = min_correlation_score
        self.max_events_per_incident = max_events_per_incident

        self.event_graph_ = nx.Graph()
        self.incidents_: List[CorrelatedIncident] = []

    def correlate(self, events: List[ForensicEvent]) -> List[CorrelatedIncident]:
        """
        Correlate a list of ForensicEvents into incidents.

        Algorithm:
          1. Build event correlation graph (nodes=events, edges=correlation scores)
          2. Apply minimum score threshold
          3. Extract connected components as incident candidates
          4. Score each incident holistically

        Args:
            events: List of normalized ForensicEvents.

        Returns:
            List of CorrelatedIncidents.
        """
        if not events:
            return []

        logger.info(f"Correlating {len(events)} events...")

        # Build the correlation graph
        G = nx.Graph()
        for event in events:
            G.add_node(event.event_id, event=event)

        n = len(events)
        n_edges = 0
        for i in range(n):
            for j in range(i + 1, n):
                e1, e2 = events[i], events[j]
                score = pairwise_correlation_score(
                    e1, e2, self.weights, self.temporal_window_sec
                )
                if score >= self.min_correlation_score:
                    G.add_edge(e1.event_id, e2.event_id, weight=score)
                    n_edges += 1

        self.event_graph_ = G
        logger.info(
            f"Event graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges "
            f"(threshold={self.min_correlation_score:.2f})"
        )

        # Extract connected components as incident candidates
        incidents = []
        for component in nx.connected_components(G):
            component_events = [
                G.nodes[node_id]["event"]
                for node_id in component
            ]

            if not component_events:
                continue

            # Compute incident-level correlation score
            if len(component_events) == 1:
                incident_score = component_events[0].confidence
            else:
                # Average pairwise score within component
                scores = []
                for i in range(len(component_events)):
                    for j in range(i + 1, len(component_events)):
                        scores.append(
                            pairwise_correlation_score(
                                component_events[i],
                                component_events[j],
                                self.weights,
                                self.temporal_window_sec,
                            )
                        )
                incident_score = float(np.mean(scores)) if scores else 0.0

            incident = CorrelatedIncident(
                correlation_score=round(incident_score, 4),
                host=component_events[0].host,
            )
            for event in sorted(component_events, key=lambda e: e.timestamp):
                incident.add_event(event)

            incidents.append(incident)

        # Sort by correlation score descending
        incidents.sort(key=lambda x: x.correlation_score, reverse=True)
        self.incidents_ = incidents

        logger.info(f"Produced {len(incidents)} correlated incidents")
        return incidents

    def get_statistics(self) -> Dict[str, Any]:
        """Return correlation engine statistics."""
        return {
            "n_events_processed": self.event_graph_.number_of_nodes(),
            "n_edges": self.event_graph_.number_of_edges(),
            "n_incidents": len(self.incidents_),
            "correlation_threshold": self.min_correlation_score,
            "temporal_window_sec": self.temporal_window_sec,
            "weight_note": (
                "HEURISTIC weights. Not experimentally optimized unless "
                "ablation study results are used."
            ),
        }
