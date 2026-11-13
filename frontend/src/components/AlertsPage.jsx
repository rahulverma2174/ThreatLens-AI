import { useCallback, useEffect, useMemo, useState } from "react";
import { ArrowUpRight, Check, ChevronDown, Download, Filter, ShieldAlert, UserRound, X } from "lucide-react";

import { apiRequest, formatDate } from "../api";

export default function AlertsPage({ alerts, initialQuery = "", onNavigate, onBulkStatusUpdate, onError }) {
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const [eventType, setEventType] = useState("");
  const [query, setQuery] = useState(initialQuery);
  const [serverAlerts, setServerAlerts] = useState(alerts);
  const [quality, setQuality] = useState(null);
  const [savingDisposition, setSavingDisposition] = useState(() => new Set());
  const [dispositionNotes, setDispositionNotes] = useState({});
  const [assigneeDrafts, setAssigneeDrafts] = useState({});
  const [savingAssignee, setSavingAssignee] = useState(() => new Set());
  const [loading, setLoading] = useState(false);
  const [selectedIds, setSelectedIds] = useState(() => new Set());
  const [bulkStatus, setBulkStatus] = useState("");
  const [savingBulk, setSavingBulk] = useState(false);
  const [dateError, setDateError] = useState("");

  const refreshQuality = useCallback(async () => {
    try {
      setQuality(await apiRequest("/api/analytics/detection-quality"));
    } catch (error) {
      onError?.(`Detection feedback summary could not be loaded: ${error.message}`);
    }
  }, [onError]);

  useEffect(() => {
    refreshQuality();
  }, [alerts, refreshQuality]);

  useEffect(() => {
    if (startDate && endDate && startDate > endDate) {
      setDateError("Start date must be on or before end date.");
      setServerAlerts([]);
      return undefined;
    }
    setDateError("");
    const params = new URLSearchParams();
    if (severity) params.set("severity", severity);
    if (status) params.set("status", status);
    if (startDate) params.set("start_date", startDate);
    if (endDate) params.set("end_date", endDate);
    if (sourceIp.trim()) params.set("source_ip", sourceIp.trim());
    if (eventType.trim()) params.set("event_type", eventType.trim());
    let active = true;
    setLoading(true);
    apiRequest(`/api/alerts${params.size ? `?${params}` : ""}`)
      .then((result) => { if (active) setServerAlerts(result); })
      .catch((error) => { if (active) onError?.(`Alerts could not be loaded: ${error.message}`); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [severity, status, startDate, endDate, sourceIp, eventType, alerts, onError]);

  const filtered = useMemo(() => serverAlerts.filter((alert) =>
    !query || `${alert.title} ${alert.source_ip} ${alert.reason} ${alert.detection_key}`.toLowerCase().includes(query.toLowerCase()),
  ), [serverAlerts, query]);
  const allVisibleSelected = filtered.length > 0 && filtered.every((alert) => selectedIds.has(alert.id));

  useEffect(() => {
    const visibleIds = new Set(filtered.map((alert) => alert.id));
    setSelectedIds((current) => {
      const next = new Set([...current].filter((id) => visibleIds.has(id)));
      return next.size === current.size ? current : next;
    });
  }, [filtered]);

  function toggleAlert(id) {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else if (next.size < 500) next.add(id);
      else onError?.("Select up to 500 alerts at a time.");
      return next;
    });
  }

  function toggleVisible() {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (allVisibleSelected) filtered.forEach((alert) => next.delete(alert.id));
      else filtered.slice(0, 500 - next.size).forEach((alert) => next.add(alert.id));
      return next;
    });
  }

  async function applyBulkStatus() {
    if (!bulkStatus || !selectedIds.size || savingBulk) return;
    setSavingBulk(true);
    try {
      const result = await onBulkStatusUpdate([...selectedIds], bulkStatus);
      const updatedById = new Map(result.alerts.map((alert) => [alert.id, alert]));
      setServerAlerts((current) => current.map((alert) => updatedById.get(alert.id) ?? alert));
      setSelectedIds(new Set());
      setBulkStatus("");
    } catch (error) {
      onError(error.message);
    } finally {
      setSavingBulk(false);
    }
  }

  async function saveDisposition(alertId, disposition, notes = "") {
    if (!disposition || savingDisposition.has(alertId)) return;
    setSavingDisposition((current) => new Set(current).add(alertId));
    try {
      const updated = await apiRequest(`/api/alerts/${alertId}/disposition`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ disposition, notes }),
      });
      setServerAlerts((current) => current.map((alert) => alert.id === alertId ? updated : alert));
      setDispositionNotes((current) => ({ ...current, [alertId]: updated.disposition_notes }));
      await refreshQuality();
    } catch (error) {
      onError?.(`Alert outcome could not be saved: ${error.message}`);
    } finally {
      setSavingDisposition((current) => {
        const next = new Set(current);
        next.delete(alertId);
        return next;
      });
    }
  }

  async function saveAssignee(alertId) {
    const alert = serverAlerts.find((item) => item.id === alertId);
    const assignee = (assigneeDrafts[alertId] ?? alert?.assignee ?? "").trim();
    if (!alert || assignee === (alert.assignee ?? "") || savingAssignee.has(alertId)) return;
    setSavingAssignee((current) => new Set(current).add(alertId));
    try {
      const updated = await apiRequest(`/api/alerts/${alertId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ assignee }),
      });
      setServerAlerts((current) => current.map((item) => item.id === alertId ? updated : item));
      setAssigneeDrafts((current) => ({ ...current, [alertId]: updated.assignee ?? "" }));
    } catch (error) {
      onError?.(`Alert owner could not be saved: ${error.message}`);
    } finally {
      setSavingAssignee((current) => {
        const next = new Set(current);
        next.delete(alertId);
        return next;
      });
    }
  }

  async function exportSelected() {
    if (!selectedIds.size) return;
    const params = new URLSearchParams();
    [...selectedIds].forEach((id) => params.append("alert_ids", String(id)));
    try {
      const response = await apiRequest(`/api/reports/alerts.csv?${params}`);
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = "threatlens-selected-alerts.csv";
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      onError?.(`Selected alerts could not be exported: ${error.message}`);
    }
  }

  return (
    <div className="page-content detection-page">
      <div className="page-heading"><div><div className="eyebrow"><ShieldAlert size={14} />RULE ENGINE <span className="heading-divider">/</span> DETECTION QUEUE</div><h1>Threat detection</h1><p>Rule-generated signals from local authentication events. Each signal needs analyst validation.</p></div><div className="heading-actions"><span className="data-scope"><i />DETECTION ENABLED</span><button className="button secondary" onClick={() => onNavigate("settings")}>Configure rules <ArrowUpRight size={13} /></button></div></div>
      <div className="detection-summary">{["critical", "high", "medium", "low"].map((level) => <div key={level} className="detection-count"><span className={`severity-marker ${level}`} /><span>{level}</span><strong>{serverAlerts.filter((alert) => alert.severity === level).length}</strong></div>)}</div>
      <section className="panel detection-quality-panel">
        <div className="panel-heading"><div><div className="section-kicker">ANALYST FEEDBACK</div><h2>Detection quality by rule</h2><p>{quality ? `${quality.reviewed_alerts} reviewed · ${quality.unreviewed_alerts} awaiting review` : "Loading analyst-labeled outcomes…"}</p></div></div>
        <div className="detection-quality-table-wrap" role="region" aria-label="Detection quality table. Scroll horizontally to view all columns." tabIndex={0}><table className="data-table"><thead><tr><th>RULE</th><th>REVIEWED</th><th>TRUE POSITIVE</th><th>FALSE POSITIVE</th><th>BENIGN</th><th>OBSERVED FP SHARE</th></tr></thead><tbody>
          {quality?.rules.map((rule) => <tr key={rule.detection_key}><td><strong className="detection-key">{rule.detection_key.replaceAll("_", " ")}</strong></td><td>{rule.reviewed_count} / {rule.alert_count}</td><td>{rule.true_positive_count}</td><td>{rule.false_positive_count}</td><td>{rule.benign_activity_count}</td><td>{rule.false_positive_share === null ? "—" : `${Math.round(rule.false_positive_share * 100)}%`}</td></tr>)}
          {quality && !quality.rules.length && <tr><td colSpan="6"><div className="empty-inline">No alerts have been generated yet. Record outcomes in the queue to build a rule-quality sample.</div></td></tr>}
        </tbody></table></div>
        {quality && <small className="detection-quality-notice">{quality.notice}</small>}
      </section>
      <section className="panel detections-panel">
        <div className="detections-toolbar"><div><strong>Detection signals</strong><span>{filtered.length} matching · {loading ? "updating" : `${serverAlerts.length} loaded`}</span></div><div className="event-filters"><label className="search-field"><Filter size={13} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search signals" aria-label="Search detection queue" /></label><label className="select-field"><ChevronDown size={13} /><select value={severity} onChange={(event) => setSeverity(event.target.value)} aria-label="Filter severity"><option value="">All severities</option>{["critical", "high", "medium", "low"].map((item) => <option key={item} value={item}>{item[0].toUpperCase() + item.slice(1)}</option>)}</select></label><label className="select-field"><select value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Filter detection status"><option value="">Any status</option>{["open", "investigating", "resolved"].map((item) => <option key={item} value={item}>{item[0].toUpperCase() + item.slice(1)}</option>)}</select><ChevronDown size={12} /></label></div></div>
        <div className="event-filters alert-extra-filters"><label className="search-field"><input type="date" value={startDate} onChange={(event) => setStartDate(event.target.value)} aria-label="Start date in UTC" /><span>From UTC</span></label><label className="search-field"><input type="date" value={endDate} onChange={(event) => setEndDate(event.target.value)} aria-label="End date in UTC" /><span>To UTC</span></label><label className="search-field"><input value={sourceIp} onChange={(event) => setSourceIp(event.target.value)} placeholder="Source IP" aria-label="Filter source IP" /></label><label className="search-field"><input value={eventType} onChange={(event) => setEventType(event.target.value)} placeholder="Event type (e.g. ssh)" aria-label="Filter event type" maxLength={32} /></label></div>
        {dateError && <div className="empty-inline" role="alert">{dateError}</div>}
        {selectedIds.size > 0 && <div className="bulk-selection-bar"><span><strong>{selectedIds.size}</strong> alerts selected</span><label className="select-field"><select value={bulkStatus} onChange={(event) => setBulkStatus(event.target.value)} aria-label="Set selected alert status"><option value="">Set status…</option>{["open", "investigating", "resolved"].map((item) => <option key={item} value={item}>{item[0].toUpperCase() + item.slice(1)}</option>)}</select><ChevronDown size={12} /></label><button className="button primary small-button" onClick={applyBulkStatus} disabled={!bulkStatus || savingBulk}>{savingBulk ? "Saving…" : <><Check size={12} />Apply to selected</>}</button><button className="inline-action" onClick={exportSelected}><Download size={12} />Export CSV</button><button className="inline-action" onClick={() => setSelectedIds(new Set())} disabled={savingBulk}><X size={12} />Clear</button><small>Each changed alert is recorded in audit history.</small></div>}
        <div className="detection-table-wrap" role="region" aria-label="Detection signals table. Scroll horizontally to review all alert fields and actions." tabIndex={0}><table className="data-table detection-table"><thead><tr><th className="event-select-cell"><input type="checkbox" checked={allVisibleSelected} onChange={toggleVisible} aria-label="Select all matching alerts" /></th><th>SEVERITY</th><th>DETECTION</th><th>SOURCE</th><th>TRIGGER</th><th>ANALYST OUTCOME</th><th>OWNER</th><th>STATUS</th><th>FIRST SEEN</th><th /></tr></thead><tbody>
          {filtered.map((alert) => <tr key={alert.id} onClick={() => onNavigate("incidents")} onKeyDown={(event) => { if (event.target === event.currentTarget && (event.key === "Enter" || event.key === " ")) { event.preventDefault(); onNavigate("incidents"); } }} tabIndex={0} aria-label={`Open incident context for alert ${alert.id}: ${alert.title}`} aria-selected={selectedIds.has(alert.id)} className={`selectable-row ${selectedIds.has(alert.id) ? "is-selected" : ""}`}><td className="event-select-cell"><input type="checkbox" checked={selectedIds.has(alert.id)} onClick={(event) => event.stopPropagation()} onChange={() => toggleAlert(alert.id)} aria-label={`Select alert ${alert.id}: ${alert.title}`} /></td><td><span className={`severity-badge ${alert.severity}`}>{alert.severity}</span></td><td><strong className="detection-name">{alert.title}</strong><small className="detection-key">{alert.detection_key.replaceAll("_", " ")}{alert.attack_technique ? ` · ATT&CK ${alert.attack_technique}` : ""}</small></td><td><code>{alert.source_ip}</code></td><td className="detection-reason">{alert.reason}</td><td><select className="alert-disposition-select" value={alert.disposition ?? ""} disabled={savingDisposition.has(alert.id)} onClick={(event) => event.stopPropagation()} onChange={(event) => saveDisposition(alert.id, event.target.value, dispositionNotes[alert.id] ?? alert.disposition_notes ?? "")} aria-label={`Analyst outcome for alert ${alert.id}`}><option value="">{savingDisposition.has(alert.id) ? "Saving…" : "Record outcome…"}</option><option value="true_positive">True positive</option><option value="false_positive">False positive</option><option value="benign_activity">Benign activity</option></select>{alert.disposition_updated_at && <small className="disposition-meta">Reviewed {formatDate(alert.disposition_updated_at)}</small>}{alert.disposition && <div className="disposition-note-edit"><input className="disposition-note-input" value={dispositionNotes[alert.id] ?? alert.disposition_notes ?? ""} disabled={savingDisposition.has(alert.id)} onClick={(event) => event.stopPropagation()} onChange={(event) => setDispositionNotes((current) => ({ ...current, [alert.id]: event.target.value }))} placeholder="Optional review note" aria-label={`Review note for alert ${alert.id}`} maxLength={4000} /><button type="button" className="disposition-note-save" disabled={savingDisposition.has(alert.id) || (dispositionNotes[alert.id] ?? alert.disposition_notes ?? "") === (alert.disposition_notes ?? "")} onClick={(event) => { event.stopPropagation(); saveDisposition(alert.id, alert.disposition, dispositionNotes[alert.id] ?? alert.disposition_notes ?? ""); }}>Save note</button></div>}</td><td><label className="alert-owner"><UserRound size={12} /><input value={assigneeDrafts[alert.id] ?? alert.assignee ?? ""} maxLength={128} placeholder="Assign owner" aria-label={`Owner for alert ${alert.id}`} disabled={savingAssignee.has(alert.id)} onClick={(event) => event.stopPropagation()} onChange={(event) => setAssigneeDrafts((current) => ({ ...current, [alert.id]: event.target.value }))} onBlur={() => saveAssignee(alert.id)} onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); event.currentTarget.blur(); } }} /></label>{savingAssignee.has(alert.id) && <small className="disposition-meta">Saving owner…</small>}</td><td><span className={`status-mini ${alert.status}`}>{alert.status}</span></td><td className="muted-cell">{formatDate(alert.created_at)}</td><td><ArrowUpRight size={14} className="row-arrow" /></td></tr>)}
          {!filtered.length && <tr><td colSpan="10"><div className="empty-inline">No matching detection signals.</div></td></tr>}
        </tbody></table></div><div className="detection-footer"><span>Rule-based detections are review signals, not confirmed attacks.</span><button className="inline-action" onClick={() => onNavigate("incidents")}>Open incident workspace <ArrowUpRight size={13} /></button></div>
      </section>
    </div>
  );
}
