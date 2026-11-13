import { useEffect, useMemo, useState } from "react";
import { Bookmark, ChevronLeft, ChevronRight, Columns3, Download, History, Search, SlidersHorizontal, Sparkles, Trash2, Upload, X } from "lucide-react";

import { apiRequest, formatDate } from "../api";
import { EventsTable } from "./EventsTable";

const PAGE_SIZE = 25;
const eventColumns = [
  ["timestamp", "Timestamp"],
  ["source_ip", "Source IP"],
  ["username", "Identity"],
  ["event_type", "Auth type"],
  ["status", "Result"],
  ["risk", "Risk"],
];
const savedSearchesKey = "threatlens.events.saved-searches";

function readSavedSearches() {
  try {
    const saved = JSON.parse(localStorage.getItem(savedSearchesKey) ?? "[]");
    return Array.isArray(saved) ? saved.filter((item) => item && typeof item.id === "string" && typeof item.name === "string") : [];
  } catch {
    return [];
  }
}

function readVisibleColumns() {
  try {
    const saved = JSON.parse(localStorage.getItem("threatlens.events.visible-columns") ?? "null");
    return Array.isArray(saved) ? saved.filter((key) => eventColumns.some(([id]) => id === key)) : eventColumns.map(([id]) => id);
  } catch {
    return eventColumns.map(([id]) => id);
  }
}

export default function EventsPage({ events, totalCount, alerts, onSearch, onNaturalSearch, onUpload, onInvestigate, onError, initialQuery = "" }) {
  const [search, setSearch] = useState(initialQuery);
  const [status, setStatus] = useState("");
  const [eventType, setEventType] = useState("");
  const [page, setPage] = useState(0);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedEvents, setSelectedEvents] = useState([]);
  const [visibleColumns, setVisibleColumns] = useState(readVisibleColumns);
  const [columnsOpen, setColumnsOpen] = useState(false);
  const [savedSearches, setSavedSearches] = useState(readSavedSearches);
  const [presetName, setPresetName] = useState("");
  const [naturalQuery, setNaturalQuery] = useState("");
  const [naturalMode, setNaturalMode] = useState(false);
  const [naturalFilters, setNaturalFilters] = useState(null);
  const [importRuns, setImportRuns] = useState([]);
  const selectedIds = useMemo(() => new Set(selectedEvents.map((event) => event.id)), [selectedEvents]);
  const selectedSourceIps = useMemo(() => new Set(selectedEvents.map((event) => event.source_ip)), [selectedEvents]);

  useEffect(() => {
    localStorage.setItem("threatlens.events.visible-columns", JSON.stringify(visibleColumns));
  }, [visibleColumns]);

  useEffect(() => {
    localStorage.setItem(savedSearchesKey, JSON.stringify(savedSearches));
  }, [savedSearches]);

  async function refreshImportRuns() {
    try {
      const result = await apiRequest("/api/ingestion/runs?limit=5");
      setImportRuns(result.runs);
    } catch (error) {
      onError?.(`Import history could not be loaded: ${error.message}`);
    }
  }

  useEffect(() => {
    refreshImportRuns();
    // Load the most recent file import runs once when the event explorer opens.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    let active = true;
    apiRequest("/api/events/saved-searches").then(async (remote) => {
      if (!active) return;
      const localOnly = savedSearches.filter((preset) => !Number.isInteger(preset.id));
      if (remote.length === 0 && localOnly.length) {
        const migrated = await Promise.all(localOnly.map(({ name, search, status, eventType }) => apiRequest("/api/events/saved-searches", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name, search, status, event_type: eventType }),
        })));
        if (active) setSavedSearches(migrated.map((item) => ({ ...item, eventType: item.event_type })));
        return;
      }
      if (active) setSavedSearches(remote.map((item) => ({ ...item, eventType: item.event_type })));
    }).catch((error) => onError?.(`Saved filters could not be loaded: ${error.message}`));
    return () => { active = false; };
    // Load once on mount; this also migrates any browser-only presets.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    setSearch(initialQuery);
    setPage(0);
    setNaturalMode(false);
    setNaturalFilters(null);
    setLoading(true);
    onSearch({ search: initialQuery, limit: PAGE_SIZE, offset: 0 }).finally(() => setLoading(false));
    // Reset on a new global-search query.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialQuery]);

  async function loadPage(nextPage = 0, forceStandard = false) {
    setLoading(true);
    setSelected(null);
    try {
      if (!forceStandard && naturalMode && naturalQuery.trim()) {
        const result = await onNaturalSearch({ query: naturalQuery.trim(), limit: PAGE_SIZE, offset: nextPage * PAGE_SIZE });
        setNaturalFilters(result.filters);
      } else {
        await onSearch({ search, status, eventType, limit: PAGE_SIZE, offset: nextPage * PAGE_SIZE });
      }
      setPage(nextPage);
    } catch (error) {
      onError?.(`Natural-language search failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  }

  async function submitNaturalSearch(event) {
    event.preventDefault();
    if (!naturalQuery.trim()) return;
    setNaturalMode(true);
    setNaturalFilters(null);
    setLoading(true);
    setSelected(null);
    try {
      const result = await onNaturalSearch({ query: naturalQuery.trim(), limit: PAGE_SIZE, offset: 0 });
      setNaturalFilters(result.filters);
      setPage(0);
    } catch (error) {
      onError?.(`Natural-language search failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  }

  async function saveCurrentSearch(event) {
    event.preventDefault();
    const name = presetName.trim();
    if (!name) return;
    try {
      const preset = await apiRequest("/api/events/saved-searches", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, search: search.trim(), status, event_type: eventType }),
      });
      setSavedSearches((current) => [{ ...preset, eventType: preset.event_type }, ...current].slice(0, 100));
      setPresetName("");
    } catch (error) {
      onError?.(`Saved filter could not be created: ${error.message}`);
    }
  }

  function applySavedSearch(preset) {
    setNaturalMode(false);
    setNaturalFilters(null);
    setSearch(preset.search);
    setStatus(preset.status);
    setEventType(preset.eventType);
    setPage(0);
    setLoading(true);
    onSearch({ search: preset.search, status: preset.status, eventType: preset.eventType, limit: PAGE_SIZE, offset: 0 }).finally(() => setLoading(false));
  }

  async function uploadFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    setBusy(true);
    try {
      await onUpload(file);
      await loadPage(0);
    } finally {
      await refreshImportRuns();
      setBusy(false);
      event.target.value = "";
    }
  }

  const pageCount = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));
  const selectedAlert = selected && alerts.find((alert) => alert.source_ip === selected.source_ip && alert.status !== "resolved");
  const risk = selectedAlert?.severity ?? (selected?.status === "failure" ? "elevated" : "low");
  function toggleSelectedEvent(event) {
    setSelectedEvents((current) => current.some((item) => item.id === event.id)
      ? current.filter((item) => item.id !== event.id)
      : [...current, event]);
  }

  function toggleCurrentPageSelection(records, currentlyAllSelected) {
    setSelectedEvents((current) => {
      if (currentlyAllSelected) return current.filter((item) => !records.some((record) => record.id === item.id));
      const byId = new Map(current.map((item) => [item.id, item]));
      records.forEach((record) => byId.set(record.id, record));
      return [...byId.values()];
    });
  }

  function exportSelection() {
    const headers = ["id", "timestamp", "ingested_at", "source_label", "source_host", "source_event_id", "source_ip", "username", "event_type", "status", "user_agent", "event_metadata_json"];
    const csvCell = (value) => {
      const text = String(value ?? "");
      const safe = /^[\s]*[=+\-@]/.test(text) ? `'${text}` : text;
      return `"${safe.replaceAll('"', '""')}"`;
    };
    const csv = [headers.join(","), ...selectedEvents.map((event) => headers.map((header) => csvCell(header === "event_metadata_json" ? JSON.stringify(event.event_metadata ?? {}) : event[header])).join(","))].join("\r\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "threatlens-selected-events.csv";
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return (
    <div className={`page-content events-page ${selected ? "with-detail" : ""}`}>
      <div className="page-heading"><div><div className="eyebrow"><span className="status-pulse" />TELEMETRY <span className="heading-divider">/</span> AUTH EVENTS</div><h1>Live monitoring</h1><p>Inspect authentication activity across the local sensor workspace.</p></div><div className="heading-actions"><label className="button secondary upload-button"><Upload size={14} />{busy ? "Importing…" : "Import logs"}<input type="file" accept=".csv,.log,.txt,.json,.jsonl,.ndjson,text/csv,text/plain,application/json" onChange={uploadFile} disabled={busy} /></label><a className="button secondary" href="/api/reports/events.csv"><Download size={14} />Export CSV</a></div></div>
      <p className="import-format-note">Import structured CSV, JSON/JSONL auth events, or a Linux <code>/var/log/auth.log</code> / <code>secure</code> file. JSON records retain supplied host, source event ID, and metadata. Each upload gets a run ID and accepted/rejected record counts.</p>
      <section className="panel import-runs-panel"><div className="import-runs-heading"><div><History size={13} /><strong>Recent import runs</strong></div><span>Latest 5 uploads</span></div>{importRuns.length ? <div className="import-runs-list">{importRuns.map((run) => <div className="import-run-row" key={run.run_id}><span className={`status-mini ${run.status}`}>{run.status}</span><strong>#{run.run_id} · {run.filename}</strong><small>{run.source_format === "linux_auth_log" ? "Linux auth.log" : run.source_format.toUpperCase()} · {run.accepted_records} accepted · {run.rejected_records} rejected · {formatDate(run.created_at)}</small>{run.error_summary && <small className="import-run-error">{run.error_summary}</small>}</div>)}</div> : <p>No file imports yet. Imported events show up in the event table below.</p>}</section>
      <div className="events-layout">
        <section className="panel events-table-panel">
          <div className="events-toolbar"><div className="events-toolbar-title"><strong>Authentication events</strong><span>{totalCount.toLocaleString()} total records</span></div>
            <form className="event-filters" onSubmit={(event) => { event.preventDefault(); setNaturalMode(false); setNaturalFilters(null); loadPage(0, true); }}>
              <label className="search-field"><Search size={14} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search IP or identity" aria-label="Search IP or identity" /></label>
              <label className="select-field"><SlidersHorizontal size={13} /><select value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Filter by result"><option value="">All results</option><option value="success">Successful</option><option value="failure">Failed</option></select></label>
              <label className="select-field type-filter"><select value={eventType} onChange={(event) => setEventType(event.target.value)} aria-label="Filter authentication type"><option value="">All auth types</option><option value="login">Login</option><option value="ssh">SSH</option><option value="vpn">VPN</option><option value="mfa">MFA</option></select></label>
              <button type="submit" className="button primary small-button">Apply filters</button>
            </form>
            <form className="natural-event-search" onSubmit={submitNaturalSearch}>
              <div className="natural-search-label"><Sparkles size={13} /><span>Ask local AI</span><small>Ollama · filter extraction only</small></div>
              <label className="search-field"><input value={naturalQuery} onChange={(event) => setNaturalQuery(event.target.value)} placeholder="e.g. failed VPN logins in the last 24 hours" aria-label="Describe events to find" maxLength={500} /></label>
              <button type="submit" className="button secondary small-button" disabled={!naturalQuery.trim() || loading}><Search size={12} />Search</button>
              {naturalMode && <button type="button" className="natural-clear" onClick={() => { setNaturalMode(false); setNaturalFilters(null); setPage(0); setLoading(true); onSearch({ search, status, eventType, limit: PAGE_SIZE, offset: 0 }).finally(() => setLoading(false)); }}>Clear AI search</button>}
            </form>
            {naturalMode && naturalFilters && <div className="natural-search-summary"><span>Interpreted filters</span>{Object.entries(naturalFilters).filter(([, value]) => value !== null).map(([key, value]) => <code key={key}>{key.replaceAll("_", " ")}: {value}</code>)}</div>}
            <div className="saved-search-row">
              <form className="saved-search-form" onSubmit={saveCurrentSearch}>
                <label className="search-field"><Bookmark size={13} /><input value={presetName} onChange={(event) => setPresetName(event.target.value)} placeholder="Name this filter set" aria-label="Name saved filter set" maxLength={40} /></label>
                <button type="submit" className="button secondary small-button" disabled={!presetName.trim()}><Bookmark size={12} />Save</button>
              </form>
              {savedSearches.length > 0 && <div className="saved-search-list" aria-label="Saved event filters">{savedSearches.map((preset) => <span className="saved-search-chip" key={preset.id}><button onClick={() => applySavedSearch(preset)} title={`Apply ${preset.name}`}>{preset.name}</button><button className="saved-search-delete" onClick={async () => { try { await apiRequest(`/api/events/saved-searches/${preset.id}`, { method: "DELETE" }); setSavedSearches((current) => current.filter((item) => item.id !== preset.id)); } catch (error) { onError?.(`Saved filter could not be deleted: ${error.message}`); } }} aria-label={`Delete ${preset.name}`} title="Delete saved filter"><Trash2 size={11} /></button></span>)}</div>}
            </div>
            <div className="event-table-actions"><div className="column-menu-wrap"><button className="button secondary small-button" onClick={() => setColumnsOpen((open) => !open)} aria-expanded={columnsOpen}><Columns3 size={13} />Columns</button>{columnsOpen && <div className="column-menu" role="group" aria-label="Visible event columns">{eventColumns.map(([id, label]) => <label key={id}><input type="checkbox" checked={visibleColumns.includes(id)} disabled={visibleColumns.includes(id) && visibleColumns.length === 1} onChange={() => setVisibleColumns((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id])} /><span>{label}</span></label>)}</div>}</div>{selectedEvents.length > 0 && <button className="button secondary small-button" onClick={() => setSelectedEvents([])}><X size={13} />Clear selection</button>}</div>
          </div>
          {selectedEvents.length > 0 && <div className="bulk-selection-bar"><span><strong>{selectedEvents.length}</strong> events selected</span><button className="inline-action" onClick={() => exportSelection()}><Download size={13} />Export selection</button><button className="inline-action" disabled={selectedSourceIps.size !== 1} onClick={() => onInvestigate([...selectedSourceIps][0])}><Search size={13} />Investigate selected IP</button><small>{selectedSourceIps.size === 1 ? [...selectedSourceIps][0] : "Select events from one IP to investigate together"}</small></div>}
          <div className="table-caption"><span><i className="caption-dot" />STORED EVENT RECORDS</span><span>Click a row to inspect event context</span></div>
          {loading && !events.length ? <div className="table-loading"><span className="status-pulse" />Loading events…</div> : <EventsTable events={events} alerts={alerts} onSelect={setSelected} selectable selectedIds={selectedIds} onToggleSelect={toggleSelectedEvent} onToggleSelectAll={toggleCurrentPageSelection} visibleColumns={visibleColumns} />}
          <div className="table-pagination"><span>Showing {totalCount ? page * PAGE_SIZE + 1 : 0}–{Math.min((page + 1) * PAGE_SIZE, totalCount)} of {totalCount}</span><div><button onClick={() => loadPage(Math.max(page - 1, 0))} disabled={page === 0 || loading} aria-label="Previous page"><ChevronLeft size={15} /></button><span>Page {page + 1} of {pageCount}</span><button onClick={() => loadPage(Math.min(page + 1, pageCount - 1))} disabled={page >= pageCount - 1 || loading} aria-label="Next page"><ChevronRight size={15} /></button></div></div>
        </section>
        {selected && <aside className="event-detail-panel"><div className="detail-topline"><span>EVENT INSPECTOR</span><button className="icon-quiet" onClick={() => setSelected(null)} aria-label="Close event details"><X size={15} /></button></div><div className="detail-id">AUTH EVENT <strong>#{selected.id}</strong></div><span className={`result-pill detail-result ${selected.status}`}>{selected.status}</span><h2>{selected.username}</h2><p className="detail-ip"><code>{selected.source_ip}</code></p><div className="detail-risk-row"><span>Risk classification</span><span className={`risk-chip ${risk}`}><i />{risk}</span></div>
          <div className="detail-fields"><div><span>Event time</span><strong>{formatDate(selected.timestamp)}</strong></div><div><span>Ingested</span><strong>{formatDate(selected.ingested_at)}</strong></div><div><span>Source</span><strong>{selected.source_label || "Legacy import"}</strong></div>{selected.import_run_id && <div><span>Import run</span><strong>#{selected.import_run_id}</strong></div>}{selected.source_host && <div><span>Source host</span><strong>{selected.source_host}</strong></div>}{selected.source_event_id && <div><span>Source record</span><strong>{selected.event_metadata?.event_id ? `Windows Event ${selected.event_metadata.event_id} · ` : ""}{selected.event_metadata?.record_id ? `Record ${selected.event_metadata.record_id}` : selected.source_event_id}</strong></div>}{selected.event_metadata?.logon_type && <div><span>Windows logon type</span><strong>{selected.event_metadata.logon_type} · {selected.event_metadata.logon_type_name}</strong></div>}{selected.event_metadata?.failure_reason && <div><span>Windows failure reason</span><strong>{selected.event_metadata.failure_reason}</strong></div>}<div><span>Authentication type</span><strong>{selected.event_type}</strong></div><div><span>Event status</span><strong className={selected.status}>{selected.status}</strong></div><div><span>User agent</span><strong>{selected.user_agent || "Not recorded"}</strong></div></div>
          <div className="detail-related"><div className="section-kicker">RELATED DETECTIONS</div>{alerts.filter((alert) => alert.source_ip === selected.source_ip).length ? alerts.filter((alert) => alert.source_ip === selected.source_ip).map((alert) => <div className="related-detection" key={alert.id}><span className={`severity-marker ${alert.severity}`} /><span><strong>{alert.title}</strong><small>{alert.severity} · {alert.status}</small></span></div>) : <p>No local detections are associated with this source.</p>}</div><button className="button secondary detail-action" onClick={() => onInvestigate(selected.source_ip)}><Search size={14} />Investigate source IP</button></aside>}
      </div>
    </div>
  );
}
