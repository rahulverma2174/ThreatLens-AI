import { useCallback, useEffect, useState } from "react";
import { Activity, Clock3, ExternalLink, Fingerprint, Plus, RefreshCw, RotateCw, Search, ShieldAlert, X } from "lucide-react";
import { apiRequest } from "../api";
import Drawer from "./ui/Drawer";

const TYPE_LABELS = { ip: "IP address", domain: "Domain", hash: "File hash" };
const STATUS_LABELS = { never_synced: "Never synced", syncing: "Syncing", fresh: "Fresh", stale: "Stale", failed: "Failed", disabled: "Disabled" };
const dateText = (value) => value ? new Date(value).toLocaleString() : "—";

const DEFAULT_MAPPING = {
  records_key: "indicators", indicator_type: "type", value: "value", confidence: "confidence",
  first_seen: "first_seen", last_seen: "last_seen", expires_at: "expires_at", reference: "reference",
};

function FeedCard({ feed, onSync, syncing, onToggle, onEdit, demoMode }) {
  return <article className="ti-feed-card">
    <div className={`ti-feed-status ${feed.freshness}`}><i />{STATUS_LABELS[feed.freshness] || feed.freshness}</div>
    <div className="ti-feed-copy"><div><strong>{feed.name}</strong><span>{feed.feed_format.toUpperCase()}</span></div><code>{feed.url}</code><small>Last success {dateText(feed.last_success_at)} · {feed.last_accepted_count} accepted · {feed.last_rejected_count} rejected</small>{feed.last_error && <small className="ti-feed-error">{feed.last_error}</small>}</div>
    {!demoMode && <div className="ti-feed-actions"><button className="ti-toggle" onClick={() => onEdit(feed)}>Edit</button><button className="button secondary small-button" onClick={() => onSync(feed)} disabled={syncing || !feed.enabled}><RotateCw size={12} />{syncing ? "Syncing…" : "Sync now"}</button><button className="ti-toggle" onClick={() => onToggle(feed)} aria-pressed={feed.enabled}>{feed.enabled ? "Disable" : "Enable"}</button></div>}
  </article>;
}

function FeedForm({ onSave, busy, editingFeed, onCancelEdit }) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ name: "", url: "", feed_format: "json", credential_env_var: "", stale_after_minutes: 1440, mapping: DEFAULT_MAPPING });
  useEffect(() => {
    if (!editingFeed) return;
    setForm({
      name: editingFeed.name,
      url: editingFeed.url,
      feed_format: editingFeed.feed_format,
      credential_env_var: editingFeed.credential_env_var || "",
      stale_after_minutes: editingFeed.stale_after_minutes,
      mapping: { ...DEFAULT_MAPPING, ...(editingFeed.field_mapping || {}) },
    });
    setOpen(true);
  }, [editingFeed]);
  const update = (key, value) => setForm((current) => ({ ...current, [key]: value }));
  const updateMapping = (key, value) => setForm((current) => ({ ...current, mapping: { ...current.mapping, [key]: value || null } }));
  const submit = async (event) => {
    event.preventDefault();
    const mapping = Object.fromEntries(Object.entries(form.mapping).map(([key, value]) => [key, value === "" ? null : value]));
    const result = await onSave({
      name: form.name, url: form.url, feed_format: form.feed_format,
      credential_env_var: form.credential_env_var || null,
      stale_after_minutes: Number(form.stale_after_minutes), field_mapping: mapping,
    }, editingFeed?.id);
    if (result) { setForm({ name: "", url: "", feed_format: "json", credential_env_var: "", stale_after_minutes: 1440, mapping: DEFAULT_MAPPING }); setOpen(false); onCancelEdit(); }
  };
  return <>
    <button className="ti-add-feed" onClick={() => setOpen((value) => !value)}><Plus size={14} />{open ? "Close feed setup" : "Configure feed"}</button>
    {open && <form className="ti-feed-form" onSubmit={submit}>
      <label>Feed name<input required minLength={2} maxLength={120} value={form.name} onChange={(event) => update("name", event.target.value)} placeholder="Organization threat feed" /></label>
      <label>HTTPS feed URL<input required type="url" value={form.url} onChange={(event) => update("url", event.target.value)} placeholder="https://feeds.example/indicators.json" /><small>Host must be allowlisted by the backend. Query strings and embedded credentials are rejected.</small></label>
      <label>Format<select value={form.feed_format} onChange={(event) => update("feed_format", event.target.value)}><option value="json">JSON</option><option value="csv">CSV</option></select></label>
      <label>Credential environment variable<input value={form.credential_env_var} onChange={(event) => update("credential_env_var", event.target.value.toUpperCase())} maxLength={128} placeholder="THREATLENS_FEED_VENDOR_TOKEN" /><small>Set the secret in the backend environment. The value is never entered or displayed here.</small></label>
      <label>Stale after (minutes)<input type="number" min="1" max="43200" value={form.stale_after_minutes} onChange={(event) => update("stale_after_minutes", event.target.value)} /></label>
      <details className="ti-field-map"><summary>Feed field mapping</summary><div className="ti-field-map-grid">{Object.entries({ records_key: "JSON records key", indicator_type: "Type field", value: "Value field", confidence: "Confidence field", first_seen: "First seen field", last_seen: "Last seen field", expires_at: "Expiry field", reference: "Reference field" }).map(([key, label]) => <label key={key}>{label}<input value={form.mapping[key] ?? ""} onChange={(event) => updateMapping(key, event.target.value)} placeholder="(not provided)" /></label>)}</div></details>
      <div className="ti-form-safety"><ShieldAlert size={13} />HTTPS, configured host allowlist, public DNS validation and response-size limits apply at sync time.</div>
      <button className="button primary" disabled={busy}>{busy ? "Saving…" : editingFeed ? "Update feed configuration" : "Save feed configuration"}</button>{editingFeed && <button className="button secondary" type="button" onClick={() => { setOpen(false); onCancelEdit(); }}>Cancel edit</button>}
    </form>}
  </>;
}

export default function ThreatIntelligencePage({ onError, onSuccess, onInvestigate, onNavigate, demoMode = false }) {
  const [feeds, setFeeds] = useState([]);
  const [editingFeed, setEditingFeed] = useState(null);
  const [iocRows, setIocRows] = useState([]);
  const [iocTotal, setIocTotal] = useState(0);
  const [filters, setFilters] = useState({ search: "", indicator_type: "", disposition: "", active: "" });
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState(null);
  const [correlation, setCorrelation] = useState(null);
  const [timeline, setTimeline] = useState(null);
  const [reviews, setReviews] = useState([]);
  const [review, setReview] = useState({ disposition: "confirmed", notes: "" });
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [savingFeed, setSavingFeed] = useState(false);
  const [syncingId, setSyncingId] = useState(null);
  const [reviewing, setReviewing] = useState(false);
  const limit = 50;

  const load = useCallback(async (nextOffset = offset) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ limit: String(limit), offset: String(nextOffset) });
      if (filters.search.trim()) params.set("search", filters.search.trim());
      if (filters.indicator_type) params.set("indicator_type", filters.indicator_type);
      if (filters.disposition) params.set("disposition", filters.disposition);
      if (filters.active) params.set("active", filters.active);
      const [feedRows, indicatorPage] = await Promise.all([
        apiRequest("/api/intelligence/feeds?limit=100"),
        apiRequest(`/api/intelligence/iocs?${params}`),
      ]);
      setFeeds(feedRows); setIocRows(indicatorPage.indicators); setIocTotal(indicatorPage.total); setOffset(nextOffset);
    } catch (error) { onError?.(`Threat intelligence data could not load: ${error.message}`); }
    finally { setLoading(false); }
  }, [filters, offset, onError]);
  useEffect(() => { load(0); }, [filters]);

  const openIndicator = async (row) => {
    setSelected(row); setDetailLoading(true); setCorrelation(null); setTimeline(null); setReviews([]);
    try {
      const [detail, matches, history, reviewRows] = await Promise.all([
        apiRequest(`/api/intelligence/iocs/${row.id}`),
        apiRequest(`/api/intelligence/iocs/${row.id}/correlation?limit=50`),
        apiRequest(`/api/intelligence/iocs/${row.id}/timeline?limit=100`),
        apiRequest(`/api/intelligence/iocs/${row.id}/reviews?limit=50`),
      ]);
      setSelected(detail); setCorrelation(matches); setTimeline(history); setReviews(reviewRows);
      setReview({ disposition: detail.analyst_disposition === "false_positive" ? "false_positive" : "confirmed", notes: "" });
    } catch (error) { onError?.(`IOC investigation could not load: ${error.message}`); }
    finally { setDetailLoading(false); }
  };

  const saveFeed = async (payload, feedId) => {
    setSavingFeed(true);
    try { await apiRequest(feedId ? `/api/intelligence/feeds/${feedId}` : "/api/intelligence/feeds", { method: feedId ? "PUT" : "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }); onSuccess?.(feedId ? "Threat feed configuration updated." : "Threat feed configuration saved."); setEditingFeed(null); await load(0); return true; }
    catch (error) { onError?.(`Feed configuration rejected: ${error.message}`); return false; }
    finally { setSavingFeed(false); }
  };
  const syncFeed = async (feed) => {
    setSyncingId(feed.id);
    try {
      const run = await apiRequest(`/api/intelligence/feeds/${feed.id}/sync`, { method: "POST" });
      onSuccess?.(`Feed sync ${run.status}: ${run.accepted_count} accepted, ${run.rejected_count} rejected.`);
      await load(0);
    } catch (error) { onError?.(`Feed sync could not start: ${error.message}`); await load(0); }
    finally { setSyncingId(null); }
  };
  const toggleFeed = async (feed) => {
    try { await apiRequest(`/api/intelligence/feeds/${feed.id}/enabled`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: !feed.enabled }) }); await load(0); }
    catch (error) { onError?.(`Feed state could not be changed: ${error.message}`); }
  };
  const submitReview = async (event) => {
    event.preventDefault(); if (!selected) return;
    setReviewing(true);
    try {
      const item = await apiRequest(`/api/intelligence/iocs/${selected.id}/reviews`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(review) });
      setReviews((current) => [item, ...current]);
      setSelected((current) => ({ ...current, analyst_disposition: item.disposition, reviewed_at: item.created_at }));
      onSuccess?.("Analyst review recorded in the audit history."); await load(offset);
    } catch (error) { onError?.(`IOC review could not be saved: ${error.message}`); }
    finally { setReviewing(false); }
  };

  return <section className="page-content threat-intelligence-page">
    <div className="page-heading ti-heading"><div><span className="eyebrow">CONTEXT · EXTERNAL SOURCES + LOCAL EVIDENCE</span><h1>Threat Intelligence</h1><p>Manage external feed provenance, review indicators and correlate IPs against locally stored authentication evidence.</p></div><button className="button secondary" onClick={() => onNavigate?.("investigation")}><Fingerprint size={13} />Open existing IP intelligence</button></div>

    <div className="ti-scope-banner"><ShieldAlert size={15} /><span>External feed confidence is shown per source and kept separate from analyst review. No indicator triggers blocking or response actions.</span></div>

    <section className="panel ti-feeds-panel"><div className="panel-heading"><div><div className="section-kicker">CONFIGURED SOURCES</div><h2>Threat intelligence feeds</h2><p>{demoMode ? "Configured feed status · management is disabled for demo access." : "Manual synchronization · secrets remain in backend environment variables."}</p></div>{!demoMode && <FeedForm onSave={saveFeed} busy={savingFeed} editingFeed={editingFeed} onCancelEdit={() => setEditingFeed(null)} />}</div>
      {feeds.length ? <div className="ti-feed-list">{feeds.map((feed) => <FeedCard key={feed.id} feed={feed} syncing={syncingId === feed.id} onSync={syncFeed} onToggle={toggleFeed} onEdit={setEditingFeed} demoMode={demoMode} />)}</div> : <div className="ti-empty">No external feeds configured. Add an HTTPS feed hosted on a backend allowlisted public host.</div>}
      <div className="ti-feed-footer">Requests disable redirects, pin validated public DNS results at connection time, and enforce time and response-size limits.</div>
    </section>

    <section className="panel ti-ioc-panel"><div className="panel-heading"><div><div className="section-kicker">DEDUPLICATED EXTERNAL INDICATORS</div><h2>Indicator inventory</h2><p>{iocTotal.toLocaleString()} normalized indicators · source confidence and expiry are independent per observation.</p></div><button className="button secondary small-button" onClick={() => load(offset)} disabled={loading}><RefreshCw size={12} />Refresh</button></div>
      <div className="ti-filterbar"><label className="ti-search"><Search size={13} /><input value={filters.search} onChange={(event) => setFilters((current) => ({ ...current, search: event.target.value }))} placeholder="Search canonical indicator" /></label><select value={filters.indicator_type} onChange={(event) => setFilters((current) => ({ ...current, indicator_type: event.target.value }))}><option value="">All types</option><option value="ip">IP</option><option value="domain">Domain</option><option value="hash">Hash</option></select><select value={filters.disposition} onChange={(event) => setFilters((current) => ({ ...current, disposition: event.target.value }))}><option value="">All review states</option><option value="unreviewed">Unreviewed</option><option value="confirmed">Analyst confirmed</option><option value="false_positive">False positive</option></select><select value={filters.active} onChange={(event) => setFilters((current) => ({ ...current, active: event.target.value }))}><option value="">Active and expired</option><option value="true">At least one active source</option><option value="false">All sources expired</option></select></div>
      <div className="ti-ioc-table-wrap" role="region" aria-label="Threat indicators table. Scroll horizontally to view all provenance and correlation fields." tabIndex={0}><table className="ti-ioc-table"><thead><tr><th>Type / indicator</th><th>Feed sources</th><th>Confidence</th><th>First seen</th><th>Last seen</th><th>Local correlation</th><th>Analyst review</th></tr></thead><tbody>{iocRows.map((ioc) => { const confidences = ioc.sources.map((source) => source.confidence).filter((value) => value != null); const isSelected = selected?.id === ioc.id; return <tr key={ioc.id} tabIndex={0} aria-selected={isSelected} className={isSelected ? "is-selected" : ""} onClick={() => openIndicator(ioc)} onKeyDown={(event) => { if (event.target === event.currentTarget && (event.key === "Enter" || event.key === " ")) { event.preventDefault(); openIndicator(ioc); } }}><td><span className={`ti-type-pill ${ioc.indicator_type}`}>{TYPE_LABELS[ioc.indicator_type]}</span><code>{ioc.value}</code></td><td>{ioc.sources.slice(0, 3).map((source) => <small className="ti-source-line" key={source.id}>{source.source_name}{source.active ? " · active" : " · expired"}</small>)}<small className="ti-source-count">{ioc.source_count} source observation{ioc.source_count === 1 ? "" : "s"}{ioc.sources.some((source) => source.expires_at) ? ` · expiry ${dateText(ioc.sources.filter((source) => source.expires_at).sort((a, b) => new Date(b.expires_at) - new Date(a.expires_at))[0]?.expires_at)}` : ""}</small></td><td>{confidences.length ? `${Math.max(...confidences)}% max` : "Not supplied"}</td><td>{ioc.first_seen ? <time dateTime={ioc.first_seen}>{dateText(ioc.first_seen)}</time> : "—"}</td><td>{ioc.last_seen ? <time dateTime={ioc.last_seen}>{dateText(ioc.last_seen)}</time> : "—"}</td><td>{ioc.correlation_status === "ip_supported" ? `${(ioc.matching_event_count ?? 0).toLocaleString()} events` : <span className="ti-uncorrelated">Schema unsupported</span>}</td><td><span className={`ti-review-state ${ioc.analyst_disposition}`}>{ioc.analyst_disposition.replaceAll("_", " ")}</span></td></tr>; })}</tbody></table>{loading && <div className="ti-table-overlay">Loading indicators…</div>}{!loading && !iocRows.length && <div className="ti-empty">No external indicators match these filters.</div>}</div>
      {iocTotal > limit && <div className="ti-pagination"><span>{offset + 1}–{Math.min(offset + limit, iocTotal)} of {iocTotal}</span><div><button disabled={!offset || loading} onClick={() => load(Math.max(0, offset - limit))}>Previous</button><button disabled={offset + limit >= iocTotal || loading} onClick={() => load(offset + limit)}>Next</button></div></div>}
    </section>

    {selected && <Drawer open onClose={() => setSelected(null)} className="ti-drawer-scrim" drawerClassName="ti-drawer" labelledBy="ti-drawer-title"><div className="ti-drawer-head"><div><span className="section-kicker">IOC INVESTIGATION · #{selected.id}</span><h2 id="ti-drawer-title">{TYPE_LABELS[selected.indicator_type]}</h2></div><button className="icon-quiet" onClick={() => setSelected(null)} aria-label="Close indicator details"><X size={15} /></button></div>
      {detailLoading ? <div className="ti-empty">Loading source evidence…</div> : <><div className="ti-indicator-value"><code>{selected.value}</code><span className={`ti-review-state ${selected.analyst_disposition}`}>{selected.analyst_disposition.replaceAll("_", " ")}</span></div>
        <div className="ti-detail-facts"><div><span>First seen</span><strong>{dateText(selected.first_seen)}</strong></div><div><span>Last seen</span><strong>{dateText(selected.last_seen)}</strong></div><div><span>Indicator active</span><strong>{selected.active ? "At least one source active" : "All observations expired"}</strong></div><div><span>Local match scope</span><strong>{selected.correlation_status === "ip_supported" ? `${selected.matching_event_count} IP event(s)` : "Unavailable: event schema lacks domain/hash"}</strong></div></div>
        <section className="ti-drawer-section"><h3>Independent source observations · {selected.source_count}</h3>{selected.sources.map((source) => <article className="ti-source-detail" key={source.id}><div><strong>{source.source_name}</strong><span>{source.confidence == null ? "Confidence not supplied" : `${source.confidence}% source confidence`} · {source.active ? "active" : "expired"}</span></div><small>Reference {source.source_reference || "(not supplied)"} · sync run #{source.latest_sync_run_id}</small><small>{dateText(source.first_seen)} → {dateText(source.last_seen)}{source.expires_at ? ` · expires ${dateText(source.expires_at)}` : " · no expiry"}</small></article>)}{selected.sources_truncated && <small>Showing the 100 most recent source observations.</small>}{!selected.sources.length && <small>No feed source observations.</small>}</section>
        {correlation && <section className="ti-drawer-section"><h3>Local event correlation</h3><p className="ti-correlate-note">{correlation.explanation}</p>{correlation.results.map((row) => <article className="ti-correlation-row" key={row.event.id}><div><time>{dateText(row.event.timestamp)}</time><strong>{row.event.username} · {row.event.status}</strong><code>{row.event.source_ip}</code><button onClick={() => onInvestigate?.(row.event.source_ip)}><ExternalLink size={11} />Open IP investigation</button></div>{row.alerts.map((alert) => <small key={`a${alert.id}`}>Alert: {alert.title} · {alert.severity}</small>)}{row.incidents.map((incident) => <small key={`i${incident.id}`}>Incident: {incident.title} · {incident.status}</small>)}</article>)}{correlation.correlation_status === "no_matches" && <small>No matching local authentication events.</small>}</section>}
        {timeline && <section className="ti-drawer-section"><h3><Activity size={13} />Investigation timeline</h3><div className="ti-timeline">{timeline.entries.map((entry, index) => <article className="ti-timeline-entry" key={`${entry.kind}-${index}`}><i className={entry.kind} /><time>{dateText(entry.occurred_at)}</time><div><strong>{entry.title}</strong><small>{entry.details.source_reference ? `Feed reference ${entry.details.source_reference}` : entry.details.notes || entry.details.detection_key || entry.details.source || "Local evidence"}</small></div></article>)}{!timeline.entries.length && <small>No timeline records.</small>}</div><small className="ti-timeline-notice">{timeline.notice}</small></section>}
        <section className="ti-drawer-section ti-review-section"><h3>Analyst disposition</h3><p>Review decisions are independent of feed confidence and recorded in the audit history.</p><form onSubmit={submitReview}><select value={review.disposition} onChange={(event) => setReview((current) => ({ ...current, disposition: event.target.value }))}><option value="confirmed">Analyst confirmed</option><option value="false_positive">False positive</option></select><textarea maxLength={2000} value={review.notes} onChange={(event) => setReview((current) => ({ ...current, notes: event.target.value }))} placeholder="Evidence and rationale" /><button className="button primary" disabled={reviewing}>{reviewing ? "Saving…" : "Record review"}</button></form>{reviews.map((item) => <div className="ti-review-history" key={item.id}><strong>{item.disposition.replaceAll("_", " ")} · {item.reviewer}</strong><time>{dateText(item.created_at)}</time>{item.notes && <small>{item.notes}</small>}</div>)}</section>
      </>}
    </Drawer>}
    <div className="ti-local-note"><Clock3 size={13} />Analyst-managed local allow/block IOCs remain available in the existing IP Intelligence workspace. They are not automatically merged with external feed observations.</div>
  </section>;
}
