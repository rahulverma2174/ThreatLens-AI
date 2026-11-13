import { useEffect, useMemo, useRef, useState } from "react";
import { useReducedMotion } from "framer-motion";
import { ArrowUpRight, CircleAlert, CircleDot, LoaderCircle, Pause, Play, RotateCcw, Search, ShieldAlert } from "lucide-react";

import { apiRequest, formatDate } from "../api";
import "./overview-globe.css";

const mobileQuery = "(max-width: 760px)";

function hasWebGL2Support() {
  try {
    const probe = document.createElement("canvas");
    const context = probe.getContext("webgl2");
    context?.getExtension("WEBGL_lose_context")?.loseContext();
    return Boolean(context);
  } catch {
    return false;
  }
}

function EntityDetails({ node, edges, nodes, onInvestigate }) {
  if (!node) return <div className="globe-detail-empty"><CircleDot size={14} /><span>Select an entity to review its local evidence.</span></div>;
  const relations = edges.filter((edge) => edge.source === node.id || edge.target === node.id).map((edge) => ({
    edge,
    node: nodes.find((item) => item.id === (edge.source === node.id ? edge.target : edge.source)),
  }));
  return <section className="globe-entity-detail" aria-label="Selected entity details">
    <div className="globe-detail-heading"><div><span className={`globe-type-dot ${node.type}`} /><span className="section-kicker">LOCAL {node.type.toUpperCase()}</span></div><span>{relations.length} relationship{relations.length === 1 ? "" : "s"}</span></div>
    <h3>{node.label}</h3>
    <div className="globe-detail-facts">
      {node.type === "event" && <><span>Outcome</span><strong>{node.status}</strong><span>Account</span><strong>{node.username}</strong><span>Source IP</span><strong><code>{node.source_ip}</code></strong><span>Source label</span><strong>{node.source_label || "Unclassified"}</strong>{node.timestamp && <><span>Event time</span><strong><time dateTime={node.timestamp}>{formatDate(node.timestamp)}</time></strong></>}</>}
      {node.type === "alert" && <><span>Severity</span><strong>{node.severity || "Not supplied"}</strong></>}
      {node.type === "incident" && <><span>Severity</span><strong>{node.severity || "Not supplied"}</strong><span>Status</span><strong>{node.status || "Not supplied"}</strong>{node.assignee && <><span>Assignee</span><strong>{node.assignee}</strong></>}{node.updated_at && <><span>Updated</span><strong><time dateTime={node.updated_at}>{formatDate(node.updated_at)}</time></strong></>}</>}
      {node.type === "ip" && <><span>Local indicator</span><strong>{node.indicator ? `${node.indicator} · analyst managed` : "None recorded"}</strong></>}
    </div>
    <div className="globe-related-evidence"><span className="section-kicker">LINKED RECORDS</span>{relations.slice(0, 5).map(({ edge, node: related }) => <div key={edge.id}><span className={`globe-type-dot ${related?.type ?? "ip"}`} /><span><strong>{related?.label ?? "Unknown entity"}</strong><small>{edge.kind.replaceAll("_", " ")}{edge.count > 1 ? ` · ${edge.count} records` : ""}</small></span></div>)}{relations.length > 5 && <small>{relations.length - 5} additional linked records</small>}{!relations.length && <small>No linked records in this graph sample.</small>}</div>
    {node.type === "ip" && <button type="button" className="button secondary small-button globe-investigate" onClick={() => onInvestigate?.(node.label)}><Search size={13} />Investigate source IP <ArrowUpRight size={13} /></button>}
  </section>;
}

function AccessibleEntityList({ nodes, edges, selectedId, onSelect }) {
  const [query, setQuery] = useState("");
  const relationCounts = useMemo(() => {
    const counts = new Map();
    for (const edge of edges) {
      counts.set(edge.source, (counts.get(edge.source) ?? 0) + 1);
      counts.set(edge.target, (counts.get(edge.target) ?? 0) + 1);
    }
    return counts;
  }, [edges]);
  const visibleNodes = useMemo(() => {
    const search = query.trim().toLowerCase();
    return nodes.filter((node) => !search || `${node.label} ${node.type}`.toLowerCase().includes(search));
  }, [nodes, query]);

  return <details className="globe-entity-browser">
    <summary>Browse local entities <span>{nodes.length}</span></summary>
    <label className="search-field"><Search size={13} /><input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter entities" aria-label="Filter local entities" /></label>
    <ul className="globe-entity-list" aria-label="Local graph entities">
      {visibleNodes.map((node) => {
        const relationCount = relationCounts.get(node.id) ?? 0;
        return <li key={node.id}><button type="button" aria-pressed={selectedId === node.id} className={selectedId === node.id ? "selected" : ""} onClick={() => onSelect(node.id)}>
          <span className={`globe-type-dot ${node.type}`} /><span><strong>{node.label}</strong><small>{node.type} · {relationCount} linked records</small></span>
        </button></li>;
      })}
      {!visibleNodes.length && <li className="globe-browser-empty">No entities match this filter.</li>}
    </ul>
  </details>;
}

export default function OverviewNetworkGlobe({ onInvestigate }) {
  const panelRef = useRef(null);
  const reduceMotion = useReducedMotion();
  const [inView, setInView] = useState(false);
  const [documentVisible, setDocumentVisible] = useState(() => typeof document === "undefined" || document.visibilityState === "visible");
  const [isMobile, setIsMobile] = useState(() => typeof window !== "undefined" && window.matchMedia(mobileQuery).matches);
  const [graph, setGraph] = useState({ nodes: [], edges: [] });
  const [hasLoaded, setHasLoaded] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [renderer, setRenderer] = useState(null);
  const [rendererError, setRendererError] = useState(false);
  const [selectedId, setSelectedId] = useState(null);
  const [hoveredId, setHoveredId] = useState(null);
  const [rotating, setRotating] = useState(true);
  const [resetToken, setResetToken] = useState(0);
  const [canvasRevision, setCanvasRevision] = useState(0);
  const selected = graph.nodes.find((node) => node.id === selectedId) ?? null;
  const hovered = graph.nodes.find((node) => node.id === hoveredId) ?? null;

  useEffect(() => {
    const element = panelRef.current;
    if (!element) return undefined;
    if (typeof IntersectionObserver === "undefined") {
      setInView(true);
      return undefined;
    }
    const observer = new IntersectionObserver(([entry]) => setInView(entry.isIntersecting), { threshold: 0.01 });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const media = window.matchMedia(mobileQuery);
    const handleChange = (event) => setIsMobile(event.matches);
    setIsMobile(media.matches);
    media.addEventListener?.("change", handleChange);
    return () => media.removeEventListener?.("change", handleChange);
  }, []);

  useEffect(() => {
    const updateVisibility = () => setDocumentVisible(document.visibilityState === "visible");
    document.addEventListener("visibilitychange", updateVisibility);
    return () => document.removeEventListener("visibilitychange", updateVisibility);
  }, []);

  useEffect(() => {
    if (!inView || !documentVisible || hasLoaded || loadError) return undefined;
    let active = true;
    setLoading(true);
    apiRequest("/api/intelligence/relationships")
      .then((data) => { if (active) { setGraph(data); setHasLoaded(true); } })
      .catch((error) => { if (active) setLoadError(error.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [documentVisible, hasLoaded, inView, loadError]);

  useEffect(() => {
    if (!inView || !documentVisible || isMobile || loading || loadError || !graph.nodes.length || renderer || rendererError) return undefined;
    if (!hasWebGL2Support()) {
      setRendererError(true);
      return undefined;
    }
    let active = true;
    import("./OverviewGlobeCanvas")
      .then((module) => { if (active) setRenderer(() => module.default); })
      .catch(() => { if (active) setRendererError(true); });
    return () => { active = false; };
  }, [documentVisible, graph.nodes.length, inView, isMobile, loadError, loading, renderer, rendererError]);

  const selectedNode = hovered ?? selected;
  const canvasFallback = <div className="globe-fallback" role="status"><ShieldAlert size={17} /><strong>3D view is unavailable</strong><span>Use the accessible local entity browser below to inspect evidence.</span><button type="button" className="button secondary small-button" onClick={() => { setRendererError(false); setCanvasRevision((value) => value + 1); }}>Retry 3D view</button></div>;
  const GlobeRenderer = renderer;

  return <section ref={panelRef} className="panel overview-globe-panel" aria-labelledby="overview-globe-title">
    <div className="panel-heading"><div><div className="section-kicker">EVIDENCE NETWORK</div><h2 id="overview-globe-title">Abstract Local Relationship Network — Not Geographic</h2><p>Sphere positions are visual only. No IP location, attack origin, or destination is represented.</p></div><div className="globe-controls" aria-label="Network visualization controls">
      {!isMobile && <button type="button" className="button secondary small-button" onClick={() => setRotating((value) => !value)} aria-pressed={rotating && !reduceMotion} disabled={reduceMotion} title={reduceMotion ? "Automatic motion is disabled by your reduced-motion preference" : undefined}>{rotating && !reduceMotion ? <Pause size={12} /> : <Play size={12} />}{reduceMotion ? "Motion reduced" : rotating ? "Pause" : "Resume"}</button>}
      {!isMobile && <button type="button" className="icon-quiet globe-reset" onClick={() => setResetToken((value) => value + 1)} aria-label="Reset network camera" title="Reset camera"><RotateCcw size={14} /></button>}
    </div></div>
    <div className="globe-provenance-note"><CircleAlert size={13} /><span>Local records from the existing relationship API. Origin labels are displayed where provided; remaining provenance is unclassified. Ambient points are decorative, not telemetry.</span><strong>{graph.nodes.length} entities · {graph.edges.length} evidence links</strong></div>
    {loading && <div className="globe-loading" role="status"><LoaderCircle size={16} /><span>Loading stored relationships…</span></div>}
    {loadError && <div className="globe-fallback" role="alert"><ShieldAlert size={17} /><strong>Local relationships could not be loaded</strong><span>{loadError}</span><button type="button" className="button secondary small-button" onClick={() => { setLoadError(""); setGraph({ nodes: [], edges: [] }); setLoading(true); }}>Retry</button></div>}
    {!loading && !loadError && !graph.nodes.length && <div className="globe-fallback" role="status"><CircleDot size={17} /><strong>No local relationships are available</strong><span>Recorded events, alerts, and incident evidence will appear here when present.</span></div>}
    {!loading && !loadError && graph.nodes.length > 0 && <>
      <div className={`globe-visualization ${isMobile ? "mobile" : ""}`} role="group" aria-label="Abstract sphere showing actual local entity relationships. Node positions are visual only and are not geographic.">
        {isMobile ? <div className="globe-mobile-visual"><div className="globe-mobile-orbit" aria-hidden="true"><span /><span /><span /></div><strong>2D evidence view</strong><span>Interactive entity details are available in the browser below.</span></div>
          : rendererError ? canvasFallback
            : GlobeRenderer ? <GlobeRenderer key={canvasRevision} canvasRevision={canvasRevision} nodes={graph.nodes} edges={graph.edges} selectedId={selectedId} hoveredId={hoveredId} onSelect={setSelectedId} onHover={setHoveredId} rotating={rotating} reducedMotion={Boolean(reduceMotion)} visible={inView && documentVisible} resetToken={resetToken} fallback={canvasFallback} />
              : <div className="globe-loading" role="status"><LoaderCircle size={16} /><span>Preparing the 3D local evidence view…</span></div>}
        {!isMobile && selectedNode && <div className="globe-hover-card" aria-live="polite"><span className={`globe-type-dot ${selectedNode.type}`} /><strong>{selectedNode.label}</strong><small>{selectedNode.type}{selectedNode.type === "event" ? ` · ${selectedNode.status} · ${selectedNode.source_label || "unclassified source"}` : " · local evidence"}</small></div>}
      </div>
      <EntityDetails node={selected} edges={graph.edges} nodes={graph.nodes} onInvestigate={onInvestigate} />
      <AccessibleEntityList nodes={graph.nodes} edges={graph.edges} selectedId={selectedId} onSelect={setSelectedId} />
    </>}
    <div className="globe-legend" aria-label="Entity type legend">{[["incident", "Incidents"], ["alert", "Alerts"], ["ip", "IP addresses"], ["user", "Users"], ["event", "Events"]].map(([type, label]) => <span key={type}><i className={`globe-type-dot ${type}`} />{label}</span>)}</div>
  </section>;
}
