import { useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { ArrowRight, Check, ChevronDown, CircleDot, Clock3, Download, FileText, ListChecks, MessageSquare, Plus, Search, ShieldAlert, UserRound, X, Sparkles } from "lucide-react";

import { apiRequest, formatDate } from "../api";
import { EventsTable } from "./EventsTable";

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
const nextStatus = { open: "investigating", investigating: "resolved", resolved: "open" };
const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);

export default function IncidentPage({ incidents, alerts = [], initialQuery = "", initialIncidentId = null, onUpdate, onError, onInvestigate }) {
  const reduceMotion = useReducedMotion();
  const [query, setQuery] = useState(initialQuery);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [selectedId, setSelectedId] = useState(initialIncidentId);
  const [notes, setNotes] = useState("");
  const [relatedEvents, setRelatedEvents] = useState([]);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [savingNotes, setSavingNotes] = useState(false);
  const [assignee, setAssignee] = useState("");
  const [newTask, setNewTask] = useState("");
  const [comments, setComments] = useState([]);
  const [commentDraft, setCommentDraft] = useState("");
  const [savingComment, setSavingComment] = useState(false);
  const [brief, setBrief] = useState(null);
  const [generatingBrief, setGeneratingBrief] = useState(false);
  const filteredIncidents = useMemo(() => incidents
    .filter((item) => (!severity || item.severity === severity) && (!status || item.status === status))
    .filter((item) => !query || `${item.title} ${item.source_ips.join(" ")} ${item.usernames.join(" ")} ${item.summary}`.toLowerCase().includes(query.toLowerCase()))
    .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity] || new Date(b.updated_at) - new Date(a.updated_at)),
  [incidents, query, severity, status]);
  const selected = filteredIncidents.find((item) => item.id === selectedId) ?? incidents.find((item) => item.id === selectedId);

  useEffect(() => {
    if (!selected) return undefined;
    setNotes(selected.analyst_notes ?? "");
    setAssignee(selected.assignee ?? "");
    setComments([]);
    setBrief(null);
    let active = true;
    setLoadingDetails(true);
    Promise.all([
      Promise.all(selected.related_event_ids.slice(0, 30).map((id) => apiRequest(`/api/events/${id}`))),
      apiRequest(`/api/incidents/${selected.id}/comments`),
    ])
      .then(([items, notes]) => { if (active) { setRelatedEvents(items); setComments(notes); } })
      .catch((error) => { if (active) onError(error.message); })
      .finally(() => { if (active) setLoadingDetails(false); });
    return () => { active = false; };
  }, [selectedId, selected?.id, onError]);

  async function saveNotes() {
    if (!selected) return;
    setSavingNotes(true);
    try { await onUpdate(selected.id, { analyst_notes: notes }); }
    finally { setSavingNotes(false); }
  }

  async function saveAssignee() {
    if (!selected || assignee === (selected.assignee ?? "")) return;
    await onUpdate(selected.id, { assignee });
  }

  async function saveTasks(nextTasks) {
    if (!selected) return;
    await onUpdate(selected.id, { tasks: nextTasks });
  }

  async function addTask(event) {
    event.preventDefault();
    const title = newTask.trim();
    if (!title || !selected || selected.tasks.length >= 30) return;
    await saveTasks([...selected.tasks, { id: crypto.randomUUID(), title, completed: false }]);
    setNewTask("");
  }

  async function addComment(event) {
    event.preventDefault();
    if (!commentDraft.trim() || !selected) return;
    setSavingComment(true);
    try {
      const added = await apiRequest(`/api/incidents/${selected.id}/comments`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ comment: commentDraft.trim() }),
      });
      setComments((current) => [added, ...current]);
      setCommentDraft("");
    } catch (error) { onError(error.message); }
    finally { setSavingComment(false); }
  }

  async function generateBrief() {
    if (!selected) return;
    setGeneratingBrief(true);
    try { setBrief(await apiRequest(`/api/incidents/${selected.id}/brief`, { method: "POST" })); }
    catch (error) { onError(error.message); }
    finally { setGeneratingBrief(false); }
  }

  function exportReport() {
    if (!selected) return;
    const eventIds = new Set(selected.related_event_ids);
    const linkedAlerts = alerts.filter((alert) => alert.related_event_ids.some((id) => eventIds.has(id)));
    const row = (label, value) => `<tr><th>${escapeHtml(label)}</th><td>${escapeHtml(value || "—")}</td></tr>`;
    const evidenceRows = relatedEvents.map((event) => `<tr><td>#${event.id}</td><td>${escapeHtml(formatDate(event.timestamp))}</td><td>${escapeHtml(event.username)}</td><td>${escapeHtml(event.source_ip)}</td><td>${escapeHtml(event.event_type)}</td><td>${escapeHtml(event.status)}</td><td>${escapeHtml(event.source_label)}</td><td>${escapeHtml(event.source_host || "—")}</td></tr>`).join("");
    const alertRows = linkedAlerts.map((alert) => `<tr><td>${escapeHtml(alert.title)}</td><td>${escapeHtml(alert.severity)}</td><td>${escapeHtml(alert.status)}</td><td>${escapeHtml(alert.assignee || "Unassigned")}</td><td>${escapeHtml(alert.disposition || "Not reviewed")}</td><td>${escapeHtml(alert.source_ip)}</td><td>${escapeHtml(alert.reason)}</td><td>${escapeHtml(alert.disposition_notes || "—")}</td></tr>`).join("");
    const taskRows = (selected.tasks ?? []).map((task) => `<li>${task.completed ? "☑" : "☐"} ${escapeHtml(task.title)}</li>`).join("");
    const commentRows = comments.map((entry) => `<article><strong>${escapeHtml(entry.actor)} · ${escapeHtml(formatDate(entry.created_at))}</strong><p>${escapeHtml(entry.details?.comment)}</p></article>`).join("");
    const briefHtml = brief ? `<section><h2>Investigation brief</h2><p>${escapeHtml(brief.summary)}</p><ul>${brief.facts.map((fact) => `<li>${escapeHtml(fact.text)}${fact.event_ids?.length ? ` <small>(Evidence: ${escapeHtml(fact.event_ids.map((id) => `#${id}`).join(", "))})</small>` : ""}</li>`).join("")}</ul><small>${escapeHtml(brief.notice)}</small></section>` : "";
    const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Incident TL-${String(selected.id).padStart(5, "0")} · ThreatLens</title><style>
      :root{font-family:Arial,sans-serif;color:#1b2733;background:#fff}body{max-width:1150px;margin:40px auto;padding:0 28px;line-height:1.5}header{border-bottom:3px solid #183d4b;padding-bottom:18px;margin-bottom:24px}header small{letter-spacing:.12em;color:#567080}h1{margin:8px 0;font-size:28px}h2{font-size:17px;margin:26px 0 8px;color:#183d4b}p{white-space:pre-wrap}table{width:100%;border-collapse:collapse;margin:10px 0 20px;font-size:11px}th,td{text-align:left;padding:8px;border:1px solid #d7e0e5;vertical-align:top;overflow-wrap:anywhere}th{background:#eef3f5}ul{padding-left:22px}article{border-left:3px solid #6e9cac;padding:3px 12px;margin:12px 0}article p{margin:4px 0}.summary{font-size:14px}.notice{margin-top:30px;padding-top:12px;border-top:1px solid #ccd5da;color:#52616c;font-size:11px}.print{position:fixed;right:20px;top:20px;padding:10px 14px;background:#173d4b;color:white;border:0;border-radius:5px;cursor:pointer}@media print{body{margin:0 auto;padding:0 5mm}.print{display:none}a{color:inherit}}
      </style></head><body><button class="print" onclick="window.print()">Print / Save as PDF</button><header><small>THREATLENS AI · LOCAL SECURITY INCIDENT REPORT</small><h1>${escapeHtml(selected.title)}</h1><div>Incident TL-${String(selected.id).padStart(5, "0")} · Generated ${escapeHtml(new Date().toLocaleString())}</div></header><section><h2>Case summary</h2><p class="summary">${escapeHtml(selected.summary)}</p><table>${row("Severity", selected.severity)}${row("Status", selected.status)}${row("Owner", selected.assignee || "Unassigned")}${row("First observed", formatDate(selected.first_seen))}${row("Last observed", formatDate(selected.last_seen))}${row("Source IPs", selected.source_ips.join(", "))}${row("Usernames", selected.usernames.join(", "))}${row("Analyst notes", selected.analyst_notes)}</table></section><section><h2>Related alerts (${linkedAlerts.length})</h2><table><thead><tr><th>Detection</th><th>Severity</th><th>Status</th><th>Owner</th><th>Review outcome</th><th>Source IP</th><th>Trigger detail</th><th>Review notes</th></tr></thead><tbody>${alertRows || '<tr><td colspan="8">No linked alert records were available.</td></tr>'}</tbody></table></section><section><h2>Authentication evidence (${relatedEvents.length} of ${selected.related_event_ids.length} linked events)</h2><table><thead><tr><th>Event</th><th>Time</th><th>Username</th><th>Source IP</th><th>Type</th><th>Result</th><th>Source label</th><th>Host</th></tr></thead><tbody>${evidenceRows || '<tr><td colspan="8">No event details are currently loaded.</td></tr>'}</tbody></table></section><section><h2>Investigation checklist</h2><ul>${taskRows || "<li>No checklist steps recorded.</li>"}</ul></section>${briefHtml}<section><h2>Case updates (${comments.length})</h2>${commentRows || "<p>No case updates recorded.</p>"}</section><p class="notice">ThreatLens findings are investigation signals. Validate the linked evidence and local data provenance before treating this report as confirmation of an attack.</p></body></html>`;
    const url = URL.createObjectURL(new Blob([html], { type: "text/html;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `ThreatLens-Incident-TL-${String(selected.id).padStart(5, "0")}.html`;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const openCount = incidents.filter((item) => item.status === "open").length;
  const investigatingCount = incidents.filter((item) => item.status === "investigating").length;
  const resolvedCount = incidents.filter((item) => item.status === "resolved").length;
  return (
    <div className={`page-content incident-page ${selected ? "incident-selected" : ""}`}>
      <div className="page-heading"><div><div className="eyebrow"><CircleDot size={13} />CASE MANAGEMENT <span className="heading-divider">/</span> RESPONSE</div><h1>Incident management</h1><p>Prioritize detections, document analyst findings, and track resolution.</p></div><div className="incident-counter"><span><i className="open-dot" />{openCount} OPEN</span><span><i className="investigating-dot" />{investigatingCount} INVESTIGATING</span><span><i className="resolved-dot" />{resolvedCount} RESOLVED</span></div></div>
      <div className="incident-workspace">
        <section className="panel incident-list-panel"><div className="incident-list-toolbar"><div><strong>Incident queue</strong><span>{filteredIncidents.length} of {incidents.length} cases</span></div><div className="event-filters"><label className="search-field"><Search size={13} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Find an incident" aria-label="Search incidents" /></label><label className="select-field"><select value={severity} onChange={(event) => setSeverity(event.target.value)} aria-label="Filter incident severity"><option value="">All severities</option>{["critical", "high", "medium", "low"].map((item) => <option key={item} value={item}>{item[0].toUpperCase() + item.slice(1)}</option>)}</select><ChevronDown size={12} /></label><label className="select-field"><select value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Filter incident status"><option value="">All statuses</option>{["open", "investigating", "resolved"].map((item) => <option key={item} value={item}>{item[0].toUpperCase() + item.slice(1)}</option>)}</select><ChevronDown size={12} /></label></div></div>
          <div className="incident-list">{filteredIncidents.map((incident) => <button key={incident.id} aria-pressed={selectedId === incident.id} className={`incident-row ${selectedId === incident.id ? "selected" : ""}`} onClick={() => setSelectedId(incident.id)}><span className={`severity-marker ${incident.severity}`} /><span className="incident-row-main"><span className="incident-row-title"><strong>{incident.title}</strong><span className={`severity-badge ${incident.severity}`}>{incident.severity}</span></span><span className="incident-row-meta"><code>{incident.source_ips.join(", ") || "No source address"}</code><span>{incident.related_event_ids.length} related events</span><time dateTime={incident.updated_at}>{formatDate(incident.updated_at)}</time></span></span><span className={`status-mini ${incident.status}`}>{incident.status}</span><ArrowRight size={14} className="row-arrow" /></button>)}{!filteredIncidents.length && <div className="empty-inline">No incidents match the selected filters.</div>}</div>
          <div className="incident-queue-footer"><ShieldAlert size={13} /> Detections are machine-generated signals. Validate context before resolution.</div>
        </section>
        <AnimatePresence mode="wait">{selected ? <motion.aside key={selected.id} className="incident-detail" initial={{ opacity: 0, x: reduceMotion ? 0 : 12 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: reduceMotion ? 0 : 8 }} transition={{ duration: reduceMotion ? 0 : .18 }}>
          <div className="incident-detail-header"><div><div className="section-kicker">INCIDENT <span>TL-{String(selected.id).padStart(5, "0")}</span></div><button className="icon-quiet mobile-detail-close" onClick={() => setSelectedId(null)} aria-label="Close incident detail"><X size={15} /></button></div><div className="incident-report-actions"><span className={`severity-badge ${selected.severity}`}>{selected.severity}</span><button className="button secondary small-button" onClick={exportReport} disabled={loadingDetails}><Download size={12} />{loadingDetails ? "Loading evidence…" : "Export report"}</button></div></div>
          <h2>{selected.title}</h2><p className="incident-explanation">{selected.summary}</p>
          <section className="incident-ai-brief"><div className="brief-heading"><div><Sparkles size={14} /><strong>Investigation brief</strong></div><button className="button secondary small-button" onClick={generateBrief} disabled={generatingBrief}>{generatingBrief ? "Building brief…" : brief ? "Refresh brief" : "Generate brief"}</button></div>{brief ? <><p>{brief.summary}</p><div className="brief-source">{brief.model_used ? "Ollama local model · grounded summary" : "Deterministic summary · local evidence"} · {brief.event_ids.length} linked event records</div><div className="brief-facts">{brief.facts.map((fact, index) => <div key={`${index}-${fact.text}`}><span>{fact.text}</span>{fact.event_ids.length > 0 && <small>Evidence: {fact.event_ids.slice(0, 8).map((id) => `#${id}`).join(", ")}{fact.event_ids.length > 8 ? ` +${fact.event_ids.length - 8}` : ""}</small>}</div>)}</div><small className="brief-notice">{brief.notice}</small></> : <p className="brief-placeholder">Generate a brief from linked events, rule alerts, local indicators, and current case status.</p>}</section>
          <div className="incident-source"><span className="section-kicker">CORRELATED SOURCE IPS</span><div className="incident-ip-list">{selected.source_ips.map((ip) => <button key={ip} onClick={() => onInvestigate(ip)}><code>{ip}</code><ArrowRight size={12} /></button>)}</div></div>
          <div className="incident-facts"><div><span>Correlated alerts</span><strong>{selected.alert_count}</strong></div><div><span>Identities</span><strong>{selected.usernames.length}</strong></div><div><span>Related activity</span><strong>{selected.related_event_ids.length} events</strong></div><div><span>Last observed</span><strong><Clock3 size={12} /><time dateTime={selected.last_seen}>{formatDate(selected.last_seen)}</time></strong></div></div>
          <div className="incident-assignee"><label htmlFor="incident-assignee"><UserRound size={14} />Owner</label><input id="incident-assignee" value={assignee} maxLength={128} placeholder="Assign analyst" onChange={(event) => setAssignee(event.target.value)} onBlur={saveAssignee} onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); event.currentTarget.blur(); } }} /></div>
          <div className="incident-status-control"><label className="section-kicker" htmlFor="incident-status">INVESTIGATION STATUS</label><div className={`status-select ${selected.status}`}><CircleDot size={14} /><select id="incident-status" value={selected.status} onChange={(event) => onUpdate(selected.id, { status: event.target.value })}><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option></select><ChevronDown size={13} /></div><button className="button primary status-advance" onClick={() => onUpdate(selected.id, { status: nextStatus[selected.status] })}><Check size={13} />{selected.status === "open" ? "Start investigation" : selected.status === "investigating" ? "Resolve incident" : "Reopen incident"}</button></div>
          <section className="incident-checklist"><div className="notes-heading"><div><ListChecks size={14} /><span>INVESTIGATION CHECKLIST</span></div><span>{(selected.tasks ?? []).filter((task) => task.completed).length}/{(selected.tasks ?? []).length}</span></div><div className="incident-task-list">{(selected.tasks ?? []).map((task) => <label key={task.id}><input type="checkbox" checked={task.completed} onChange={() => saveTasks(selected.tasks.map((item) => item.id === task.id ? { ...item, completed: !item.completed } : item))} /><span className={task.completed ? "completed" : ""}>{task.title}</span></label>)}{!selected.tasks?.length && <p>No investigation steps yet.</p>}</div><form onSubmit={addTask}><input value={newTask} onChange={(event) => setNewTask(event.target.value)} placeholder="Add a response or investigation step" maxLength={200} /><button className="icon-quiet" type="submit" disabled={!newTask.trim() || (selected.tasks?.length ?? 0) >= 30} aria-label="Add checklist item"><Plus size={15} /></button></form></section>
          <div className="analyst-notes"><div className="notes-heading"><div><FileText size={13} /><span>ANALYST NOTES</span></div><span>{notes.length}/4000</span></div><textarea aria-label="Analyst notes" maxLength={4000} value={notes} onChange={(event) => setNotes(event.target.value)} placeholder="Record triage context, validation steps, and resolution notes…" /><button className="button secondary save-notes" onClick={saveNotes} disabled={savingNotes || notes === (selected.analyst_notes ?? "")}>{savingNotes ? "Saving…" : "Save notes"}</button></div>
          <section className="incident-comments"><div className="notes-heading"><div><MessageSquare size={14} /><span>CASE COMMENTS</span></div><span>{comments.length}</span></div><form onSubmit={addComment}><textarea aria-label="Add an incident update" value={commentDraft} onChange={(event) => setCommentDraft(event.target.value)} maxLength={2000} placeholder="Add an update for the investigation…" /><button className="button secondary" disabled={!commentDraft.trim() || savingComment}>{savingComment ? "Posting…" : "Post update"}</button></form><div className="incident-comment-list">{comments.map((entry) => <article key={entry.id}><div><strong>{entry.actor}</strong><time dateTime={entry.created_at}>{formatDate(entry.created_at)}</time></div><p>{entry.details.comment}</p></article>)}{!comments.length && <p>No case updates yet.</p>}</div></section>
          <div className="related-events"><div className="section-kicker">RELATED AUTH EVENTS <span>{selected.related_event_ids.length}</span></div>{loadingDetails ? <div className="table-loading"><span className="status-pulse" />Loading linked events…</div> : <EventsTable events={relatedEvents.slice(0, 5)} compact />}</div>
        </motion.aside> : <aside className="incident-detail incident-detail-empty"><div className="empty-icon"><ShieldAlert size={18} /></div><strong>Select an incident</strong><span>Review detection context, linked events, and analyst notes.</span></aside>}</AnimatePresence>
      </div>
    </div>
  );
}
