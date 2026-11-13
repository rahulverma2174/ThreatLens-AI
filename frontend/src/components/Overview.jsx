import { useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { createPortal } from "react-dom";
import { Activity, ArrowDownRight, ArrowUpRight, Bell, ChevronDown, ChevronUp, CircleCheck, Clock3, RefreshCw, Settings2, ShieldAlert, Siren, X } from "lucide-react";
import { Area, AreaChart, CartesianGrid, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis } from "recharts";

import { apiRequest, formatDate } from "../api";
import { EventsTable } from "./EventsTable";
import OverviewNetworkGlobe from "./OverviewNetworkGlobe";
import Button from "./ui/Button";
import MetricCard from "./ui/MetricCard";
import "./overview-customize.css";

const colors = { critical: "#ff5b67", high: "#ff9c5b", medium: "#f0c65e", low: "#49d6aa" };
const widgetDefinitions = [
  { id: "activity", label: "Authentication timeline" },
  { id: "network", label: "Abstract local relationship network" },
  { id: "severity", label: "Threat severity" },
  { id: "sources", label: "Top source IPs" },
  { id: "incidents", label: "Active incident queue" },
  { id: "events", label: "Recent events" },
  { id: "feed", label: "Detection activity" },
  { id: "operations", label: "Operational health" },
];
const defaultWidgetOrder = ["activity", "network", "sources", "incidents", "events", "severity", "feed", "operations"];
const widgetStorageKey = "threatlens.command-center.widgets.v3";
const activityWindows = [
  { value: 24, label: "24 hours" },
  { value: 168, label: "7 days" },
  { value: 720, label: "30 days" },
];

function readWidgetPreferences() {
  try {
    const stored = JSON.parse(localStorage.getItem(widgetStorageKey) ?? "null");
    const valid = Array.isArray(stored?.order) ? stored.order.filter((id) => defaultWidgetOrder.includes(id)) : [];
    return {
      order: [...new Set([...valid, ...defaultWidgetOrder])],
      hidden: Array.isArray(stored?.hidden) ? stored.hidden.filter((id) => defaultWidgetOrder.includes(id)) : [],
    };
  } catch {
    return { order: defaultWidgetOrder, hidden: [] };
  }
}

function fillActivityHours(buckets, windowHours) {
  const byHour = new Map(buckets.map((bucket) => [Math.floor(new Date(bucket.time).getTime() / 3_600_000) * 3_600_000, bucket]));
  const lastHour = Math.floor(Date.now() / 3_600_000) * 3_600_000;
  const firstHour = lastHour - windowHours * 3_600_000;
  return Array.from({ length: windowHours + 1 }, (_, index) => {
    const timestamp = firstHour + index * 3_600_000;
    const bucket = byHour.get(timestamp);
    return { timestamp, success: bucket?.success ?? 0, failure: bucket?.failure ?? 0 };
  });
}

function formatActivityTime(value, windowHours, withDate = false) {
  const options = windowHours <= 24
    ? { hour: "2-digit", minute: "2-digit", hour12: false }
    : { month: "short", day: "2-digit", hour: "2-digit", hour12: false };
  return new Intl.DateTimeFormat(undefined, withDate ? { ...options, year: "numeric", timeZoneName: "short" } : options).format(new Date(value));
}

function topIPs(events, alerts) {
  const map = new Map();
  for (const event of events) {
    if (event.status !== "failure") continue;
    const item = map.get(event.source_ip) ?? { ip: event.source_ip, failures: 0, users: new Set() };
    item.failures += 1;
    item.users.add(event.username);
    map.set(event.source_ip, item);
  }
  return [...map.values()].map((item) => ({
    ...item,
    severity: alerts.find((alert) => alert.source_ip === item.ip && alert.status !== "resolved")?.severity ?? "low",
  })).sort((a, b) => b.failures - a.failures).slice(0, 5);
}

export default function Overview({
  stats, events, alerts, incidents, sources: sourceRegistry = [], eventCount, apiStatus, monitoringEnabled,
  refreshing, lastRefresh, onRefresh, onNavigate, onInvestigate, onError, loading,
}) {
  const [preferences, setPreferences] = useState(readWidgetPreferences);
  const [customizeOpen, setCustomizeOpen] = useState(false);
  const customizeTriggerRef = useRef(null);
  const customizeCloseRef = useRef(null);
  const reduceMotion = useReducedMotion();
  const [activityWindow, setActivityWindow] = useState(168);
  const [activityResponse, setActivityResponse] = useState(null);
  const [activityLoading, setActivityLoading] = useState(true);
  useEffect(() => {
    localStorage.setItem(widgetStorageKey, JSON.stringify(preferences));
  }, [preferences]);

  useEffect(() => {
    if (!customizeOpen) return undefined;
    const bodyOverflow = document.body.style.overflow;
    const mainShell = document.querySelector(".main-shell");
    const mainOverflow = mainShell?.style.overflowY ?? "";
    document.body.style.overflow = "hidden";
    if (mainShell && window.matchMedia("(min-width: 768px)").matches) mainShell.style.overflowY = "hidden";
    customizeCloseRef.current?.focus();
    const dismissAndTrapFocus = (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setCustomizeOpen(false);
        return;
      }
      if (event.key !== "Tab") return;
      const drawer = document.getElementById("overview-customize-drawer");
      const focusable = [...(drawer?.querySelectorAll('button:not(:disabled), input:not(:disabled), [href], select:not(:disabled), [tabindex]:not([tabindex="-1"])') ?? [])];
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && (document.activeElement === first || !drawer?.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !drawer?.contains(document.activeElement))) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", dismissAndTrapFocus);
    return () => {
      document.removeEventListener("keydown", dismissAndTrapFocus);
      document.body.style.overflow = bodyOverflow;
      if (mainShell) mainShell.style.overflowY = mainOverflow;
      customizeTriggerRef.current?.focus();
    };
  }, [customizeOpen]);

  useEffect(() => {
    let active = true;
    setActivityLoading(true);
    apiRequest(`/api/dashboard/activity?window_hours=${activityWindow}`)
      .then((data) => { if (active) setActivityResponse(data); })
      .catch((error) => { if (active) onError?.(`Activity timeline could not be loaded: ${error.message}`); })
      .finally(() => { if (active) setActivityLoading(false); });
    return () => { active = false; };
  }, [activityWindow, onError]);

  const openAlerts = alerts.filter((alert) => alert.status !== "resolved");
  const activeIncidents = incidents.filter((incident) => incident.status !== "resolved");
  const sourceHealth = sourceRegistry.map((source) => {
    const seenAt = source.last_seen_at ? new Date(source.last_seen_at).getTime() : NaN;
    const online = Boolean(source.enabled && Number.isFinite(seenAt) && Date.now() - seenAt < 90_000);
    return { ...source, health: !source.enabled ? "paused" : online ? "online" : "awaiting", online };
  });
  const onlineSources = sourceHealth.filter((source) => source.online).length;
  const enabledSources = sourceHealth.filter((source) => source.enabled).length;
  const severityCounts = stats?.unresolved_alerts_by_severity ?? {};
  const metrics = [
    { label: "Authentication events", value: stats?.total_events, icon: Activity, tone: "cyan", scope: "All stored" },
    { label: "Failed logins", value: stats?.failed_logins, icon: ArrowDownRight, tone: "amber", scope: "All stored" },
    { label: "Critical alerts", value: severityCounts.critical, icon: ShieldAlert, tone: "red", scope: "Unresolved" },
    { label: "High alerts", value: stats?.high_alerts ?? severityCounts.high, icon: ArrowUpRight, tone: "orange", scope: "Unresolved" },
    { label: "Medium alerts", value: stats?.medium_alerts ?? severityCounts.medium, icon: Activity, tone: "yellow", scope: "Unresolved" },
    { label: "Open incidents", value: stats?.open_incidents, icon: Siren, tone: "blue", scope: "Open status" },
  ];
  const activity = useMemo(() => fillActivityHours(activityResponse?.buckets ?? [], activityWindow), [activityResponse, activityWindow]);
  const severity = ["critical", "high", "medium", "low"].map((name) => ({ name, value: severityCounts[name] ?? 0, fill: colors[name] }));
  const topSourceIPs = useMemo(() => topIPs(events, alerts), [events, alerts]);
  const feed = [
    ...openAlerts.map((alert) => ({ kind: "alert", timestamp: alert.created_at, severity: alert.severity, title: alert.title, detail: `${alert.source_ip} · ${alert.related_event_ids.length} related events`, id: alert.id })),
    ...events.slice(0, 12).map((event) => ({ kind: "event", timestamp: event.timestamp, severity: event.status === "failure" ? "medium" : "low", title: `${event.status === "failure" ? "Failed" : "Successful"} authentication · ${event.username}`, detail: `${event.source_ip} · ${event.event_type}`, id: `event-${event.id}` })),
  ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 6);

  function moveWidget(id, direction) {
    setPreferences((current) => {
      const order = [...current.order];
      const index = order.indexOf(id);
      const target = index + direction;
      if (target < 0 || target >= order.length) return current;
      [order[index], order[target]] = [order[target], order[index]];
      return { ...current, order };
    });
  }

  function toggleWidget(id) {
    setPreferences((current) => ({
      ...current,
      hidden: current.hidden.includes(id) ? current.hidden.filter((item) => item !== id) : [...current.hidden, id],
    }));
  }

  const widgets = {
    network: <OverviewNetworkGlobe onInvestigate={onInvestigate} />,
    activity: <section className="panel activity-panel soc-widget widget-activity"><div className="panel-heading"><div><div className="section-kicker">AUTHENTICATION TELEMETRY</div><h2>Security activity timeline</h2><p>{activityResponse?.events_count?.toLocaleString() ?? "—"} records in the selected {activityWindow === 24 ? "day" : activityWindow === 168 ? "7-day" : "30-day"} window</p></div><div className="activity-panel-actions"><label className="select-field activity-window-select"><span className="sr-only">Timeline period</span><select value={activityWindow} onChange={(event) => setActivityWindow(Number(event.target.value))} aria-label="Activity timeline period">{activityWindows.map((window) => <option key={window.value} value={window.value}>{window.label}</option>)}</select></label><div className="chart-legend"><span><i className="legend-success" />Successful</span><span><i className="legend-failure" />Failed</span></div></div></div>
      <div className="activity-chart">{activityResponse?.events_count ? <ResponsiveContainer width="100%" height="100%"><AreaChart data={activity} margin={{ top: 12, right: 7, left: -20, bottom: 0 }}><defs><linearGradient id="okFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#55c49c" stopOpacity={.14} /><stop offset="100%" stopColor="#55c49c" stopOpacity={0} /></linearGradient><linearGradient id="failFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#ef7880" stopOpacity={.13} /><stop offset="100%" stopColor="#ef7880" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke="#26333d" strokeDasharray="2 6" vertical={false} /><XAxis dataKey="timestamp" tickFormatter={(value) => formatActivityTime(value, activityWindow)} tick={{ fill: "#9aabb5", fontSize: 10 }} axisLine={false} tickLine={false} minTickGap={28} /><Tooltip labelFormatter={(value) => `${formatActivityTime(value, activityWindow, true)} · ${new Date(value).toISOString()}`} contentStyle={{ background: "#121c25", border: "1px solid #354854", borderRadius: 6, color: "#e8eff4", fontSize: 11 }} /><Area type="monotone" dataKey="success" name="Successful" stroke="#55c49c" strokeWidth={2} fill="url(#okFill)" /><Area type="monotone" dataKey="failure" name="Failed" stroke="#ef7880" strokeWidth={2} fill="url(#failFill)" /></AreaChart></ResponsiveContainer> : <div className="chart-empty"><Activity size={19} /><span>{activityLoading || loading ? "Loading authentication telemetry…" : "No stored events in this time window."}</span></div>}</div><div className="chart-footnote"><span><i className="footnote-dot" />Bucketed by UTC event time · labels in local timezone</span><span>{activityResponse?.events_count?.toLocaleString() ?? 0} events</span></div>
    </section>,
    severity: <section className="panel severity-panel soc-widget widget-severity"><div className="panel-heading"><div><div className="section-kicker">DETECTION OUTPUT</div><h2>Threat severity</h2><p>Unresolved rule-generated signals</p></div><button className="icon-quiet" onClick={() => onNavigate("alerts")} aria-label="Open threat detections"><ArrowUpRight size={14} /></button></div>
      <div className="severity-chart-wrap">{openAlerts.length ? <><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={severity.filter((item) => item.value > 0)} dataKey="value" nameKey="name" innerRadius="69%" outerRadius="91%" paddingAngle={3} stroke="none" /><Tooltip contentStyle={{ background: "#111a27", border: "1px solid #2a3848", borderRadius: 3, color: "#e5edf6", fontSize: 10 }} /></PieChart></ResponsiveContainer><div className="donut-center"><strong>{openAlerts.length}</strong><span>OPEN SIGNALS</span></div></> : <div className="chart-empty"><ShieldAlert size={18} /><span>No unresolved signals</span></div>}</div>
      <div className="severity-legend">{severity.map((item) => <div key={item.name}><i style={{ background: item.fill }} /><span>{item.name}</span><strong>{item.value}</strong></div>)}</div><button className="inline-action" onClick={() => onNavigate("alerts")}>Review detection queue <ArrowUpRight size={13} /></button>
    </section>,
    sources: <section className="panel top-ip-panel soc-widget widget-sources"><div className="panel-heading"><div><div className="section-kicker">SOURCE ANALYSIS</div><h2>Top observed source IPs</h2><p>Ranked by failed logins in the current event sample</p></div><button className="inline-action compact-action" onClick={() => onNavigate("investigation")}>Investigate IP <ArrowUpRight size={13} /></button></div>
      {topSourceIPs.length ? <div className="top-ip-list">{topSourceIPs.map((item, index) => <button className="top-ip-row" key={item.ip} onClick={() => onInvestigate(item.ip)}><span className="ip-rank">{String(index + 1).padStart(2, "0")}</span><span className="ip-main"><code>{item.ip}</code><small>{item.users.size} username{item.users.size === 1 ? "" : "s"} observed</small></span><span className="ip-failures"><strong>{item.failures}</strong><small>failures</small></span><span className={`risk-chip ${item.severity}`}><i />{item.severity}</span><ArrowUpRight size={13} className="ip-open" /></button>)}</div> : <div className="empty-inline">No failed login activity in the current event sample.</div>}
    </section>,
    incidents: <section className="panel incidents-panel soc-widget widget-incidents"><div className="panel-heading"><div><div className="section-kicker">RESPONSE WORKSPACE</div><h2>Active incident queue</h2><p>Correlated incidents requiring analyst review</p></div><button className="inline-action compact-action" onClick={() => onNavigate("incidents")}>All incidents <ArrowUpRight size={13} /></button></div>
      {activeIncidents.length ? <div className="incident-preview-list">{activeIncidents.slice(0, 5).map((incident) => <button className="incident-preview" key={incident.id} onClick={() => onNavigate("incidents")}><span className={`severity-marker ${incident.severity}`} /><span className="incident-preview-copy"><strong>TL-{String(incident.id).padStart(5, "0")} · {incident.title}</strong><small>{incident.assignee ? `Owner: ${incident.assignee} · ` : "Unassigned · "}{incident.related_event_ids.length} events · updated {formatDate(incident.updated_at)}</small></span><span className={`status-mini ${incident.status}`}>{incident.status}</span></button>)}</div> : <div className="empty-inline">No active incidents. The queue is clear.</div>}
    </section>,
    events: <section className="panel recent-events-panel soc-widget widget-events"><div className="panel-heading"><div><div className="section-kicker">EVENT EXPLORER</div><h2>Recent authentication events</h2></div><button className="inline-action" onClick={() => onNavigate("events")}>Open event explorer <ArrowUpRight size={13} /></button></div><EventsTable events={events.slice(0, 5)} compact alerts={alerts} /></section>,
    feed: <section className="panel feed-panel soc-widget widget-feed"><div className="panel-heading"><div><div className="section-kicker">LOCAL ACTIVITY</div><h2>Detection activity</h2></div><span className="feed-live"><i />STORED DATA</span></div><div className="activity-feed">{feed.map((item) => <div className="feed-item" key={`${item.kind}-${item.id}`}><span className={`feed-icon ${item.kind} ${item.severity}`}>{item.kind === "alert" ? <ShieldAlert size={12} /> : item.severity === "medium" ? <ArrowDownRight size={12} /> : <CircleCheck size={12} />}</span><span className="feed-copy"><strong>{item.title}</strong><small>{item.detail}</small><time>{formatDate(item.timestamp)}</time></span></div>)}{!feed.length && <div className="empty-inline"><Bell size={14} />No stored event or detection activity.</div>}</div><button className="inline-action" onClick={() => onNavigate("audit")}>View analyst activity <ArrowUpRight size={13} /></button></section>,
    operations: <section className="panel operations-panel soc-widget widget-operations"><div className="panel-heading"><div><div className="section-kicker">SYSTEM OBSERVABILITY</div><h2>Operational health</h2><p>Live API and local data coverage</p></div><span className={`health-state ${apiStatus === "Connected" ? "healthy" : "unavailable"}`}><i />{apiStatus}</span></div>
        <div className="operations-grid"><div><span className="operations-label">API CONNECTION</span><strong>{apiStatus}</strong><small>FastAPI health endpoint</small></div><div><span className="operations-label">DETECTION ENGINE</span><strong>{monitoringEnabled ? "Enabled" : "Paused"}</strong><small>Rule processing setting</small></div><div><span className="operations-label">DATA SOURCES</span><strong>{sourceRegistry.length} configured · {enabledSources} enabled</strong><small>{sourceRegistry.length ? "Windows source registry" : "No collector source configured"}</small></div><div><span className="operations-label">SOURCE CHECK-INS</span><strong>{onlineSources} online</strong><small>Heartbeat received in the last 90 seconds</small></div><div><span className="operations-label">ANOMALY MODEL</span><strong>On-demand analysis</strong><small>{eventCount >= 10 ? "Run from AI Analysis; results are not automatic" : "Requires at least 10 events for model inference"}</small></div><div><span className="operations-label">LAST OBSERVED EVENT</span><strong>{events[0] ? formatDate(events[0].timestamp) : "Unavailable"}</strong><small>Event time, not ingestion time</small></div></div>
        <div className="source-health-overview">
          <div className="source-health-heading"><div><strong>Collector health</strong><small>Current state from source registry heartbeats</small></div><span>{onlineSources} / {enabledSources} online</span></div>
          {sourceHealth.length ? <>
            <div className="source-health-bar" role="img" aria-label={`${onlineSources} of ${enabledSources} enabled collectors online; ${sourceHealth.length - enabledSources} paused`}>
              {sourceHealth.filter((source) => source.health === "online").length > 0 && <i className="online" style={{ flex: sourceHealth.filter((source) => source.health === "online").length }} />}
              {sourceHealth.filter((source) => source.health === "awaiting").length > 0 && <i className="awaiting" style={{ flex: sourceHealth.filter((source) => source.health === "awaiting").length }} />}
              {sourceHealth.filter((source) => source.health === "paused").length > 0 && <i className="paused" style={{ flex: sourceHealth.filter((source) => source.health === "paused").length }} />}
            </div>
            <div className="source-health-list">{sourceHealth.map((source) => <div className="source-health-row" key={source.id}>
              <span className={`source-health-state ${source.health}`}><i aria-hidden="true" />{source.health === "awaiting" ? "No recent check-in" : source.health}</span>
              <strong>{source.name}</strong>
              <time dateTime={source.last_seen_at || undefined}>{source.last_seen_at ? `Last check-in ${formatDate(source.last_seen_at)}` : "Never connected"}</time>
            </div>)}</div>
          </> : <div className="source-health-empty">No collectors are registered. Configure a Windows source to see check-in health here.</div>}
        </div>
    </section>,
  };

  const widgetMap = new Map(widgetDefinitions.map(({ id }) => [id, widgets[id]]));
  const visibleWidgets = preferences.order.filter((id) => !preferences.hidden.includes(id));

  return (
    <div className="page-content overview-page">
      <div className="page-heading overview-heading">
        <div><div className="eyebrow"><span className="status-pulse" />SOC COMMAND CENTER <span className="heading-divider">/</span> LOCAL AUTH TELEMETRY</div><h1>Security overview</h1><p>Operational view of stored authentication events and locally generated detection signals.</p></div>
        <div className="overview-heading-right"><span className="environment-tag" title="The application does not infer whether stored events are synthetic or imported.">LOCAL WORKSPACE · PROVENANCE UNCLASSIFIED</span><Button variant="secondary" onClick={onRefresh} disabled={refreshing} loading={refreshing} icon={<RefreshCw size={13} />}>{refreshing ? "Refreshing…" : "Refresh data"}</Button><button ref={customizeTriggerRef} type="button" className="button secondary" onClick={() => setCustomizeOpen(true)} aria-expanded={customizeOpen} aria-haspopup="dialog" aria-controls="overview-customize-drawer"><Settings2 size={13} />Customize</button></div>
      </div>
      {typeof document !== "undefined" && createPortal(<AnimatePresence>
        {customizeOpen && [
          <motion.div key="overview-customize-backdrop" className="widget-customize-backdrop" aria-hidden="true" onClick={(event) => { if (event.target === event.currentTarget) setCustomizeOpen(false); }} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: reduceMotion ? 0.08 : 0.18 }} />,
          <motion.aside key="overview-customize-drawer" id="overview-customize-drawer" className="widget-customize" role="dialog" aria-modal="true" aria-labelledby="widget-customize-title" initial={{ x: reduceMotion ? 0 : 28, opacity: reduceMotion ? 0 : 0.7 }} animate={{ x: 0, opacity: 1 }} exit={{ x: reduceMotion ? 0 : 20, opacity: 0 }} transition={{ duration: reduceMotion ? 0.08 : 0.2, ease: "easeOut" }}>
            <div className="widget-customize-head"><div><span className="widget-customize-kicker">OVERVIEW SETTINGS</span><strong id="widget-customize-title">Dashboard widgets</strong><small>Choose what appears and set the reading order.</small></div><button ref={customizeCloseRef} type="button" className="icon-quiet" onClick={() => setCustomizeOpen(false)} aria-label="Close customization"><X size={17} /></button></div>
            <div className="widget-customize-list">{preferences.order.map((id, index) => { const definition = widgetDefinitions.find((item) => item.id === id); if (!definition) return null; return <div className="widget-config-row" key={id}><label><input type="checkbox" checked={!preferences.hidden.includes(id)} onChange={() => toggleWidget(id)} /><span>{definition.label}</span></label><div><button type="button" onClick={() => moveWidget(id, -1)} disabled={index === 0} aria-label={`Move ${definition.label} up`}><ChevronUp size={15} /></button><button type="button" onClick={() => moveWidget(id, 1)} disabled={index === preferences.order.length - 1} aria-label={`Move ${definition.label} down`}><ChevronDown size={15} /></button></div></div>; })}</div>
            <p className="widget-customize-note">Visibility and order are saved in this browser.</p>
          </motion.aside>,
        ]}
      </AnimatePresence>, document.body)}
      <div className="metric-strip overview-kpis">
        {metrics.map(({ label, value, icon, tone, scope }, index) => <MetricCard key={label} label={label} value={value ?? 0} icon={icon} tone={tone} description={scope} loading={loading} index={index} />)}
      </div>
      <div className="dashboard-context-strip"><span><i className={`health-dot ${apiStatus === "Connected" ? "good" : "bad"}`} />API {apiStatus}</span><span><i className={`health-dot ${monitoringEnabled ? "good" : "warn"}`} />Detection {monitoringEnabled ? "enabled" : "paused"}</span><span><i className={`health-dot ${sourceRegistry.some((source) => source.enabled) ? "good" : "warn"}`} />{sourceRegistry.length ? `${sourceRegistry.filter((source) => source.enabled).length}/${sourceRegistry.length} sources enabled` : "No data sources configured"}</span><span><Clock3 size={12} />{lastRefresh ? `Refreshed ${formatDate(lastRefresh)}` : "Waiting for first refresh"}</span><span>Latest {events.length} of {eventCount.toLocaleString()} records loaded</span></div>
      <div className="overview-widget-grid">{visibleWidgets.map((id) => <motion.div key={id} layout className={`widget-slot widget-slot-${id}`} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: .18 }}>{widgetMap.get(id)}</motion.div>)}</div>
      {!visibleWidgets.length && <div className="empty-state dashboard-empty"><div className="empty-icon"><Settings2 size={16} /></div><strong>All dashboard widgets are hidden</strong><button className="button secondary" onClick={() => setCustomizeOpen(true)}>Choose widgets</button></div>}
    </div>
  );
}
