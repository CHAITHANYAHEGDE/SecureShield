"""
secureshield.correlation.graph
================================
Attack event graph representation using NetworkX.

Nodes: processes, files, users, IPs, domains, events, ML detections
Edges: spawned, created, modified, executed, connected_to, resolved_to,
       correlated_with, detected_by

The graph provides:
  - Visual representation of the attack chain
  - Path analysis between processes and network artifacts
  - Centrality analysis to identify key nodes (e.g., pivot processes)
  - Exportable to GraphML/JSON for visualization tools
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx

from secureshield.forensics.schema import CorrelatedIncident, EventType, ForensicEvent
from secureshield.common.logging_utils import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Node type constants
# ---------------------------------------------------------------------------

class NodeType:
    PROCESS = "process"
    FILE = "file"
    IP = "ip_address"
    DOMAIN = "domain"
    USER = "user"
    EVENT = "event"
    ML_DETECTION = "ml_detection"
    SERVICE = "service"


# ---------------------------------------------------------------------------
# Attack Graph Builder
# ---------------------------------------------------------------------------

class AttackGraphBuilder:
    """
    Constructs a directed attack graph from a CorrelatedIncident.

    The graph allows investigators to trace the attack chain from initial
    compromise through lateral movement to impact.
    """

    def __init__(self):
        self.G = nx.DiGraph()

    def reset(self) -> None:
        self.G = nx.DiGraph()

    def _add_node(self, node_id: str, node_type: str, **attrs) -> str:
        """Add a node if it doesn't exist, otherwise update attrs."""
        if not self.G.has_node(node_id):
            self.G.add_node(node_id, node_type=node_type, **attrs)
        else:
            self.G.nodes[node_id].update(attrs)
        return node_id

    def _add_edge(self, src: str, dst: str, edge_type: str, **attrs) -> None:
        """Add a directed edge."""
        self.G.add_edge(src, dst, edge_type=edge_type, **attrs)

    def build_from_incident(self, incident: CorrelatedIncident) -> nx.DiGraph:
        """
        Build an attack graph from a correlated incident.

        Args:
            incident: CorrelatedIncident from the correlation engine.

        Returns:
            Directed graph representing the incident's attack chain.
        """
        self.reset()
        events_sorted = sorted(incident.events, key=lambda e: e.timestamp)

        # Track previous process node for chain building
        prev_proc_id = None
        prev_event_id = None

        for event in events_sorted:
            # ── Event node ─────────────────────────────────────────────────
            evt_id = self._add_node(
                event.event_id,
                NodeType.EVENT,
                event_type=event.event_type.value,
                timestamp=event.timestamp.isoformat(),
                severity=event.severity.value,
                confidence=event.confidence,
                synthetic=event.synthetic,
            )

            # ── Process node ───────────────────────────────────────────────
            if event.process or event.pid:
                proc_label = f"{event.process or 'unknown'}:{event.pid or '?'}"
                proc_id = self._add_node(
                    f"PROC:{proc_label}",
                    NodeType.PROCESS,
                    name=event.process or "unknown",
                    pid=event.pid,
                    host=event.host,
                )
                self._add_edge(proc_id, evt_id, "triggered", weight=1.0)

                # Parent-child relationship
                if event.parent_process or event.ppid:
                    parent_label = f"{event.parent_process or 'unknown'}:{event.ppid or '?'}"
                    parent_id = self._add_node(
                        f"PROC:{parent_label}",
                        NodeType.PROCESS,
                        name=event.parent_process or "unknown",
                        pid=event.ppid,
                    )
                    self._add_edge(parent_id, proc_id, "spawned", weight=0.9)

                # Process chain
                if prev_proc_id and prev_proc_id != f"PROC:{proc_label}":
                    self._add_edge(prev_proc_id, f"PROC:{proc_label}", "correlated_with", weight=0.5)
                prev_proc_id = f"PROC:{proc_label}"

            # ── File node ──────────────────────────────────────────────────
            if event.file or event.file_path:
                file_label = event.file_path or event.file or "unknown_file"
                file_id = self._add_node(
                    f"FILE:{file_label}",
                    NodeType.FILE,
                    name=file_label,
                    file_hash=event.file_hash,
                )
                edge_type = {
                    EventType.FILE_CREATION: "created",
                    EventType.FILE_MODIFICATION: "modified",
                    EventType.FILE_EXECUTION: "executed",
                }.get(event.event_type, "accessed")
                self._add_edge(evt_id, file_id, edge_type, weight=0.8)

            # ── Network nodes ──────────────────────────────────────────────
            if event.dst_ip:
                ip_id = self._add_node(f"IP:{event.dst_ip}", NodeType.IP, address=event.dst_ip)
                self._add_edge(evt_id, ip_id, "connected_to", port=event.dst_port, weight=0.9)

            if event.domain:
                dom_id = self._add_node(f"DOM:{event.domain}", NodeType.DOMAIN, name=event.domain)
                self._add_edge(evt_id, dom_id, "resolved_to", weight=0.8)
                if event.dst_ip:
                    self._add_edge(f"DOM:{event.domain}", f"IP:{event.dst_ip}", "resolves_to", weight=1.0)

            # ── ML Detection node ──────────────────────────────────────────
            if event.event_type == EventType.ML_DETECTION:
                ml_id = self._add_node(
                    f"ML:{event.event_id}",
                    NodeType.ML_DETECTION,
                    model=event.ml_model,
                    prediction=event.ml_prediction,
                    confidence=event.ml_confidence,
                )
                self._add_edge(evt_id, ml_id, "detected_by", weight=event.ml_confidence or 0.5)

            # ── User node ──────────────────────────────────────────────────
            if event.user:
                user_id = self._add_node(f"USER:{event.user}", NodeType.USER, name=event.user)
                self._add_edge(user_id, evt_id, "initiated", weight=0.7)

            prev_event_id = evt_id

        logger.info(
            f"Attack graph: {self.G.number_of_nodes()} nodes, "
            f"{self.G.number_of_edges()} edges"
        )
        return self.G

    def get_centrality_analysis(self) -> Dict[str, Any]:
        """
        Compute graph centrality metrics to identify key nodes (e.g., pivot processes).
        """
        if self.G.number_of_nodes() == 0:
            return {}

        try:
            degree_centrality = nx.degree_centrality(self.G)
            # In-degree centrality (nodes many others point to)
            in_centrality = nx.in_degree_centrality(self.G)
            # Out-degree centrality (nodes that trigger many others)
            out_centrality = nx.out_degree_centrality(self.G)

            # Top 5 nodes by degree centrality
            top_nodes = sorted(degree_centrality.items(), key=lambda x: x[1], reverse=True)[:5]

            return {
                "top_central_nodes": [
                    {
                        "node": n,
                        "degree_centrality": round(d, 4),
                        "in_centrality": round(in_centrality.get(n, 0), 4),
                        "out_centrality": round(out_centrality.get(n, 0), 4),
                        "node_type": self.G.nodes[n].get("node_type", "unknown"),
                    }
                    for n, d in top_nodes
                ],
                "n_nodes": self.G.number_of_nodes(),
                "n_edges": self.G.number_of_edges(),
                "is_connected": nx.is_weakly_connected(self.G) if self.G.number_of_nodes() > 1 else True,
            }
        except Exception as e:
            logger.warning(f"Centrality analysis failed: {e}")
            return {"error": str(e)}

    def to_dict(self) -> Dict[str, Any]:
        """Export graph as JSON-serializable dict."""
        return nx.node_link_data(self.G)

    def save(self, output_path: str | Path) -> None:
        """Save graph to JSON."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(nx.node_link_data(self.G), f, indent=2, default=str)
        logger.info(f"Attack graph saved: {output_path}")

    def save_graphml(self, output_path: str | Path) -> None:
        """Save graph to GraphML format for external visualization."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        nx.write_graphml(self.G, str(output_path))
        logger.info(f"GraphML saved: {output_path}")
