import { memo, useEffect, useMemo, useState } from "react";
import { Background, Controls, Handle, MiniMap, Position, ReactFlow } from "@xyflow/react";
import { ArrowRight, Filter, Network, RefreshCw, Search, ShieldAlert, X } from "lucide-react";

import { apiRequest, formatDate } from "../api";

import "@xyflow/react/dist/style.css";

const entityLabels = { incident: "INCIDENT", alert: "DETECTION", ip: "SOURCE IP", user: "ACCOUNT", event: "AUTH EVENT" };

const GraphEntityNode = memo(function GraphEntityNode({ data, selected }) {
  return <div className={`relationship-entity-node type-${data.entityType} ${selected ? "selected" : ""}`} aria-hidden="true">
    <Handle type="target" position={Position.Left} aria-hidden="true" />
    <span className="relationship-entity-mark" aria-hidden="true">{data.entityType.slice(0, 2).toUpperCase()}</span>
    <span className="relationship-entity-copy"><small>{entityLabels[data.entityType] ?? data.entityType.toUpperCase()}</small><strong>{data.label}</strong>{data.detail && <small>{data.detail}</small>}</span>
    <Handle type="source" position={Position.Right} aria-hidden="true" />
  </div>;
});
const graphNodeTypes = { entity: GraphEntityNode };

export default function RelationshipsPage({ onError, onInvestigate }) {
  const [graph, setGraph] = useState({ nodes: [], edges: [] });
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState("");
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState(null);
  const [loading, setLoading] = useState(true);
  const selectedNode = graph.nodes.find((node) => node.id === selectedNodeId);
  const selectedRelationships = selectedNode
    ? graph.edges.filter((edge) => edge.source === selectedNode.id || edge.target === selectedNode.id)
      .map((edge) => ({ ...edge, node: graph.nodes.find((node) => node.id === (edge.source === selectedNode.id ? edge.target : edge.source)) }))
    : [];

  async function loadGraph() {
    setLoading(true);
    try {
      setGraph(await apiRequest("/api/intelligence/relationships"));
    } catch (error) {
      onError(error.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadGraph();
  }, []);

  const visibleGraph = useMemo(() => {
    const term = query.trim().toLowerCase();
    const matchingIds = new Set(
      graph.nodes.filter((node) => !term || node.label.toLowerCase().includes(term)).map((node) => node.id),
    );
    const edges = graph.edges.filter((edge) =>
      (!kind || edge.kind === kind)
      && (!term || matchingIds.has(edge.source) || matchingIds.has(edge.target)),
    );
    const ids = new Set(term ? matchingIds : kind ? [] : graph.nodes.map((node) => node.id));
    for (const edge of edges) {
      ids.add(edge.source);
      ids.add(edge.target);
    }
    const nodes = graph.nodes.filter((node) => ids.has(node.id)).map((node) => ({ ...node }));
    const highlightedIds = new Set(graph.nodes.filter((node) => term && node.label.toLowerCase().includes(term)).map((node) => node.id));
    const layers = { incident: 0, alert: 1, ip: 2, user: 3, event: 4 };
    const positions = { incident: new Map(), alert: new Map(), ip: new Map(), user: new Map(), event: new Map() };
    const relationCounts = new Map();
    for (const edge of graph.edges) {
      relationCounts.set(edge.source, (relationCounts.get(edge.source) ?? 0) + 1);
      relationCounts.set(edge.target, (relationCounts.get(edge.target) ?? 0) + 1);
    }
    for (const node of nodes) {
      const layer = layers[node.type] ?? 1;
      const index = positions[node.type].size;
      positions[node.type].set(node.id, index);
      node.position = { x: 70 + layer * 270, y: 80 + index * 105 };
      const entityType = node.type;
      const incidentDetail = entityType === "incident" ? `${node.status ?? "status unavailable"} · ${node.severity ?? "severity unavailable"}` : "";
      const alertDetail = entityType === "alert" ? `${node.severity ?? "severity unavailable"} severity` : "";
      const ipDetail = entityType === "ip" ? (node.indicator ? `${node.indicator} · analyst managed` : "No local indicator") : "";
      const eventDetail = entityType === "event" ? `${node.status} · ${node.source_label || "Unclassified source"}` : "";
      const detail = incidentDetail || alertDetail || ipDetail || eventDetail;
      const relationCount = relationCounts.get(node.id) ?? 0;
      node.data = { label: node.label, entityType, indicator: node.indicator, detail, accessibleLabel: `${entityLabels[entityType] ?? entityType} ${node.label}${detail ? `, ${detail}` : ""}, ${relationCount} linked records` };
      node.ariaLabel = node.data.accessibleLabel;
      node.type = "entity";
      node.style = { width: entityType === "incident" || entityType === "alert" ? 184 : 172, padding: 0, border: 0, borderRadius: 0, background: "transparent", boxShadow: "none" };
      node.className = highlightedIds.has(node.id) ? "is-match" : query.trim() ? "is-context" : "";
      node.sourcePosition = "right";
      node.targetPosition = "left";
      node.selected = node.id === selectedNodeId;
    }
    return {
      nodes,
        edges: edges.map((edge) => ({
        ...edge,
        label: `${edge.kind.replaceAll("_", " ")}${edge.count > 1 ? ` · ${edge.count}` : ""}`,
        animated: false,
        selected: edge.id === selectedEdgeId,
        style: {
          stroke: edge.kind === "failure" ? "#fb6175" : edge.kind === "success" ? "#51c99b" : edge.kind.includes("incident") ? "#a18cff" : edge.kind === "alert" || edge.kind.includes("alert") ? "#ff9a60" : "#4bd3e9",
          strokeWidth: edge.id === selectedEdgeId ? 2.8 : selectedNodeId && (edge.source === selectedNodeId || edge.target === selectedNodeId) ? 2.3 : 1.4,
          opacity: selectedNodeId && edge.source !== selectedNodeId && edge.target !== selectedNodeId ? 0.24 : 0.84,
          transition: "stroke .16s ease, stroke-width .16s ease, opacity .16s ease",
        },
        labelStyle: { fill: "#a6b5c8", fontSize: 9 },
        labelBgStyle: { fill: "#101827", fillOpacity: 0.94 },
        labelBgPadding: [4, 3],
        labelBgBorderRadius: 4,
      })),
    };
  }, [graph, kind, query, selectedNodeId, selectedEdgeId]);

  const indicatorCount = graph.nodes.filter((node) => node.type === "ip" && node.indicator).length;
  const timeline = graph.nodes.filter((node) => node.type === "event").sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  return (
    <div className="page-content relationships-page">
      <div className="page-heading"><div><div className="eyebrow"><Network size={13} />LOCAL TELEMETRY <span className="heading-divider">/</span> ENTITY CORRELATION</div><h1>Attack relationships</h1><p>Explore observed IP, account, and rule-alert links from local authentication events. Edges represent records, not attribution.</p></div><button className="button secondary" onClick={loadGraph} disabled={loading}><RefreshCw size={13} />{loading ? "Refreshing…" : "Refresh graph"}</button></div>
      <div className="relationship-summary"><span><i className="graph-dot ip-dot" />{graph.nodes.filter((node) => node.type === "ip").length} source IPs</span><span><i className="graph-dot user-dot" />{graph.nodes.filter((node) => node.type === "user").length} usernames</span><span><i className="graph-dot alert-dot" />{graph.nodes.filter((node) => node.type === "alert").length} rule signals</span><span><i className="graph-dot incident-dot" />{graph.nodes.filter((node) => node.type === "incident").length} incidents</span><span><i className="graph-dot indicator-dot" />{indicatorCount} local indicators</span><small>Recent bounded sample · no external intelligence</small></div>
      <div className={`relationship-workspace ${selectedNode ? "has-node-detail" : ""}`}>
      <section className="panel relationship-panel">
        <div className="relationship-toolbar"><div className="section-kicker"><Filter size={12} />GRAPH FILTERS</div><div className="event-filters"><label className="search-field"><Search size={13} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter node labels" aria-label="Filter graph nodes" /></label><label className="select-field"><select value={kind} onChange={(event) => setKind(event.target.value)} aria-label="Filter relationship type"><option value="">All relationships</option>{[...new Set(graph.edges.map((edge) => edge.kind))].map((edgeKind) => <option key={edgeKind} value={edgeKind}>{edgeKind.replaceAll("_", " ")}</option>)}</select></label>{(query || kind) && <button type="button" className="button secondary small-button" onClick={() => { setQuery(""); setKind(""); }} aria-label="Clear graph filters">Clear filters</button>}</div></div>
        <div className="relationship-canvas">{loading ? <div className="table-loading"><span className="status-pulse" />Loading local relationships…</div> : visibleGraph.nodes.length ? <ReactFlow aria-label="Interactive graph of locally observed entities and evidence relationships" nodes={visibleGraph.nodes} edges={visibleGraph.edges} nodeTypes={graphNodeTypes} nodesFocusable nodesConnectable={false} fitView fitViewOptions={{ padding: 0.2 }} minZoom={0.12} maxZoom={1.8} onlyRenderVisibleElements onNodeClick={(_, node) => { setSelectedNodeId(node.id); setSelectedEdgeId(null); }} onEdgeClick={(_, edge) => { setSelectedEdgeId(edge.id); setSelectedNodeId(edge.source); }}><Background color="#253247" gap={22} size={1} /><Controls showInteractive={false} /><MiniMap nodeColor={(node) => ["alert", "incident"].includes(node.data?.entityType) || node.data?.indicator === "blocklist" ? "#ff747b" : node.data?.entityType === "user" ? "#78aaff" : node.data?.entityType === "event" ? "#a78bfa" : node.data?.indicator === "allowlist" ? "#59d5a5" : "#51d8ef"} maskColor="#080d1888" /></ReactFlow> : <div className="empty-state"><div className="empty-icon"><ShieldAlert size={16} /></div><strong>No matching graph relationships</strong><span>Import or record local authentication events to build this view.</span></div>}</div>
        <div className="relationship-mobile-entities" role="region" aria-label="Relationship entity list">{visibleGraph.nodes.map((node) => { const original = graph.nodes.find((item) => item.id === node.id); const relationCount = graph.edges.filter((edge) => edge.source === node.id || edge.target === node.id).length; return <button type="button" key={node.id} aria-pressed={selectedNodeId === node.id} className={selectedNodeId === node.id ? "selected" : ""} onClick={() => { setSelectedNodeId(node.id); setSelectedEdgeId(null); }}><span className={`graph-dot ${original?.type === "user" ? "user-dot" : ["alert", "incident"].includes(original?.type) ? "alert-dot" : original?.type === "event" ? "event-dot" : "ip-dot"}`} /><span><strong>{original?.label ?? node.id}</strong><small>{original?.type ?? "entity"} · {relationCount} linked records</small></span><ArrowRight size={14} /></button>; })}{!visibleGraph.nodes.length && !loading && <div className="empty-inline">No relationship entities match the current filters.</div>}</div>
        <div className="relationship-footnote">Source: most recent 250 stored events and 100 rule alerts. Allowlist/blocklist labels are analyst-managed and not independently verified.</div>
      </section>
      {selectedNode && <aside className="panel relationship-node-detail"><div className="relationship-detail-head"><div><span className="section-kicker">OBSERVED ENTITY</span><strong>{selectedNode.type.toUpperCase()}</strong></div><button className="icon-quiet" onClick={() => { setSelectedNodeId(null); setSelectedEdgeId(null); }} aria-label="Close node details"><X size={14} /></button></div><h2>{selectedNode.label}</h2><p>Links are derived from locally stored authentication records and rule detections.</p>{selectedNode.timestamp && <div className="selected-event-metadata"><span>Event time</span><strong><time dateTime={selectedNode.timestamp}>{formatDate(selectedNode.timestamp)}</time></strong><span>Principal</span><strong>{selectedNode.username}</strong><span>Source address</span><strong><code>{selectedNode.source_ip}</code></strong><span>Source</span><strong>{selectedNode.source_label}</strong></div>}{selectedNode.indicator && <span className={`indicator-badge ${selectedNode.indicator}`}>{selectedNode.indicator} · analyst managed</span>}{selectedNode.severity && <span className={`severity-badge ${selectedNode.severity}`}>{selectedNode.severity} rule signal</span>}{selectedEdgeId && <div className="relationship-selected-evidence"><span className="section-kicker">SELECTED EVIDENCE LINK</span><strong>{graph.edges.find((edge) => edge.id === selectedEdgeId)?.kind.replaceAll("_", " ")}</strong><small>{graph.edges.find((edge) => edge.id === selectedEdgeId)?.count ?? 1} linked record(s) · endpoints and direction reflect the stored relationship record.</small></div>}<div className="relationship-detail-evidence"><span className="section-kicker">DIRECT RELATIONSHIPS · {selectedRelationships.length}</span>{selectedRelationships.map((relation) => <button type="button" key={relation.id} aria-pressed={relation.id === selectedEdgeId} className={relation.id === selectedEdgeId ? "selected" : ""} onClick={() => setSelectedEdgeId(relation.id)}><span className={`graph-dot ${relation.node?.type === "user" ? "user-dot" : ["alert", "incident"].includes(relation.node?.type) ? "alert-dot" : "ip-dot"}`} /><span><strong>{relation.node?.label ?? "Unknown entity"}</strong><small>{relation.kind === "alert" ? "rule signal" : `${relation.count} ${relation.kind.replaceAll("_", " ")}`}</small></span></button>)}{!selectedRelationships.length && <span className="muted-cell">No direct links in the current bounded sample.</span>}</div>{selectedNode.type === "ip" && <button className="button secondary relationship-investigate" onClick={() => onInvestigate(selectedNode.label)}><Search size={13} />Investigate source IP <ArrowRight size={13} /></button>}</aside>}
      </div>
      <section className="panel storyline-timeline"><div className="panel-heading"><div><div className="section-kicker">CHRONOLOGICAL EVIDENCE</div><h2>Authentication event timeline</h2><p>Most recent event records in the graph sample, ordered by event timestamp.</p></div><span className="model-tag">{timeline.length} EVENTS</span></div><div className="storyline-list">{timeline.slice(0, 100).map((event) => <button key={event.id} className={`storyline-event ${event.status}`} onClick={() => setSelectedNodeId(event.id)}><i /><time dateTime={event.timestamp}>{formatDate(event.timestamp)}</time><strong>{event.label}</strong><code>{event.source_ip}</code><small>{event.source_label} · {event.event_type}</small></button>)}{!timeline.length && <div className="empty-inline">No event timeline evidence is available yet.</div>}</div></section>
    </div>
  );
}
