import { useCallback, useEffect, useMemo, useState } from "react";
import { Download, Play, Plus, Save, Search, Trash2 } from "lucide-react";
import { apiRequest } from "../api";
import EmptyState from "./ui/EmptyState";
import FormField from "./ui/FormField";
import LoadingState from "./ui/LoadingState";
import Pagination from "./ui/Pagination";

const FIELD_OPTIONS = [
  ["source_ip", "Source IP"], ["username", "Username"], ["event_type", "Event type"], ["result", "Result"], ["severity", "Alert severity"],
];
const defaultRange = () => {
  const end = new Date();
  const start = new Date(end.getTime() - 24 * 60 * 60 * 1000);
  return { start_time: start.toISOString(), end_time: end.toISOString() };
};
const localInputValue = (value) => {
  const date = new Date(value);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
};

function ConditionRow({ condition, onChange, onRemove }) {
  const valueOptions = condition.field === "result"
    ? ["failure", "success"]
    : condition.field === "severity" ? ["critical", "high", "medium", "low", "unclassified"] : null;
  return <div className="hunt-condition-row">
    <select aria-label="Condition field" value={condition.field} onChange={(event) => onChange({ ...condition, field: event.target.value, operator: "equals", value: "" })}>
      {FIELD_OPTIONS.map(([value, label]) => <option value={value} key={value}>{label}</option>)}
    </select>
    {condition.field === "username" ? <select aria-label="Condition operator" value={condition.operator} onChange={(event) => onChange({ ...condition, operator: event.target.value })}><option value="equals">is exactly</option><option value="contains">contains</option></select> : <span className="hunt-equals">is</span>}
    {valueOptions ? <select aria-label="Condition value" value={condition.value} onChange={(event) => onChange({ ...condition, value: event.target.value })}><option value="">Select value…</option>{valueOptions.map((value) => <option key={value}>{value}</option>)}</select> : <input aria-label="Condition value" value={condition.value} maxLength={128} placeholder={condition.field === "source_ip" ? "192.0.2.10" : `Enter ${condition.field.replace("_", " ")}`} onChange={(event) => onChange({ ...condition, value: event.target.value })} />}
    <button className="hunt-remove" onClick={onRemove} aria-label="Remove condition"><Trash2 size={14} /></button>
  </div>;
}

export default function ThreatHuntingPage({ onError, onNavigate, onInvestigate, onOpenIncident }) {
  const [range, setRange] = useState(defaultRange);
  const [logic, setLogic] = useState("AND");
  const [conditions, setConditions] = useState([{ field: "result", operator: "equals", value: "failure" }]);
  const [saved, setSaved] = useState([]);
  const [results, setResults] = useState(null);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveName, setSaveName] = useState("");
  const [saveOpen, setSaveOpen] = useState(false);

  const query = useMemo(() => ({ ...range, logic, conditions }), [range, logic, conditions]);
  const loadSaved = useCallback(async () => {
    try { setSaved(await apiRequest("/api/hunting/queries")); }
    catch (error) { onError?.(`Saved hunts could not be loaded: ${error.message}`); }
  }, [onError]);
  useEffect(() => { loadSaved(); }, [loadSaved]);

  const runHunt = useCallback(async (pageOffset = 0) => {
    setLoading(true);
    try {
      const response = await apiRequest("/api/hunting/search", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ query, limit: 50, offset: pageOffset }) });
      setResults(response);
      setOffset(pageOffset);
    } catch (error) { onError?.(`Hunt could not run: ${error.message}`); }
    finally { setLoading(false); }
  }, [query, onError]);

  const updateCondition = (index, next) => setConditions((current) => current.map((condition, item) => item === index ? next : condition));
  const setDate = (key, value) => { if (value) setRange((current) => ({ ...current, [key]: new Date(value).toISOString() })); };
  const applySaved = (item) => {
    setRange({ start_time: item.query.start_time, end_time: item.query.end_time });
    setLogic(item.query.logic);
    setConditions(item.query.conditions);
    setResults(null);
  };
  const saveQuery = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      await apiRequest("/api/hunting/queries", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: saveName, description: "", query }) });
      setSaveName(""); setSaveOpen(false); await loadSaved();
    } catch (error) { onError?.(`Hunt could not be saved: ${error.message}`); }
    finally { setSaving(false); }
  };
  const exportCsv = async () => {
    setExporting(true);
    try {
      const response = await apiRequest("/api/hunting/export", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ query, max_rows: 5000 }) });
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a"); link.href = url; link.download = "threatlens-hunt.csv"; link.click(); URL.revokeObjectURL(url);
    } catch (error) { onError?.(`Hunt export failed: ${error.message}`); }
    finally { setExporting(false); }
  };
  const deleteSaved = async (item) => {
    try { await apiRequest(`/api/hunting/queries/${item.id}`, { method: "DELETE" }); setSaved((current) => current.filter((entry) => entry.id !== item.id)); }
    catch (error) { onError?.(`Saved hunt could not be deleted: ${error.message}`); }
  };
  return <section className="page-content threat-hunting-page">
    <div className="page-heading hunt-heading"><div><span className="eyebrow">INVESTIGATE · HISTORICAL AUTHENTICATION</span><h1>Threat Hunting</h1><p>Build constrained queries against locally stored authentication events and inspect linked cases.</p></div><div className="hunt-heading-mark"><Search size={18} /><span>LOCAL EVENT RECORDS</span></div></div>
    <div className="hunt-layout">
      <aside className="panel hunt-builder">
        <div className="panel-heading"><div><h2>Query builder</h2><p>Time range is always applied. Conditions use the selected logic.</p></div></div>
        <div className="hunt-builder-body">
          <div className="hunt-date-grid"><FormField label="From" htmlFor="hunt-start-time"><input id="hunt-start-time" type="datetime-local" value={localInputValue(range.start_time)} onChange={(event) => setDate("start_time", event.target.value)} /></FormField><FormField label="To" htmlFor="hunt-end-time"><input id="hunt-end-time" type="datetime-local" value={localInputValue(range.end_time)} onChange={(event) => setDate("end_time", event.target.value)} /></FormField></div>
          <div className="hunt-condition-header"><strong>Conditions</strong><select value={logic} aria-label="Condition logic" onChange={(event) => setLogic(event.target.value)}><option>AND</option><option>OR</option></select></div>
          <div className="hunt-condition-list">{conditions.map((condition, index) => <ConditionRow key={index} condition={condition} onChange={(next) => updateCondition(index, next)} onRemove={() => setConditions((current) => current.filter((_, item) => item !== index))} />)}</div>
          <button className="hunt-add-condition" disabled={conditions.length >= 20} onClick={() => setConditions((current) => [...current, { field: "username", operator: "equals", value: "" }])}><Plus size={14} />Add condition <span>{conditions.length}/20</span></button>
          <div className="hunt-actions"><button className="hunt-run" disabled={loading || !conditions.length} onClick={() => runHunt(0)}><Play size={14} />{loading ? "Running…" : "Run hunt"}</button><button disabled={exporting} onClick={exportCsv}><Download size={14} />{exporting ? "Preparing…" : "Export CSV"}</button></div>
          <button className="hunt-save-toggle" onClick={() => setSaveOpen((open) => !open)}><Save size={14} />Save this query</button>
          {saveOpen && <form className="hunt-save-form" onSubmit={saveQuery}><input required minLength={3} maxLength={100} value={saveName} onChange={(event) => setSaveName(event.target.value)} placeholder="Name this hunt" /><button disabled={saving}>{saving ? "Saving…" : "Save"}</button></form>}
        </div>
        <div className="hunt-saved"><div className="hunt-saved-title"><strong>Saved hunts</strong><span>{saved.length}</span></div>{saved.length ? saved.map((item) => <div className="hunt-saved-item" key={item.id}><button onClick={() => applySaved(item)} title={item.description || item.name}>{item.name}</button><button onClick={() => deleteSaved(item)} aria-label={`Delete ${item.name}`}><Trash2 size={13} /></button></div>) : <p>No saved hunts yet.</p>}</div>
      </aside>

      <div className="hunt-results-column">
        <section className="panel hunt-results-panel">
          <div className="panel-heading hunt-result-heading"><div><h2>Matching events</h2><p>{results ? `${results.total.toLocaleString()} matching records · ${results.execution_ms.toFixed(1)} ms` : "Run a query to populate the investigation table."}</p></div>{results && <span className="hunt-count">{results.results.length} shown</span>}</div>
          {loading && <LoadingState className="hunt-state" label="Querying local event records…" />}
          {!loading && results?.results.length > 0 && <div className="hunt-table-wrap" role="region" aria-label="Threat hunt results table. Scroll horizontally to view event and related evidence." tabIndex={0}><table className="hunt-table"><thead><tr><th>Timestamp</th><th>User</th><th>Source IP</th><th>Type / result</th><th>Alert / incident evidence</th></tr></thead><tbody>{results.results.map(({ event, alerts, incidents }) => <tr key={event.id}><td>{new Date(event.timestamp).toLocaleString()}</td><td className="hunt-user">{event.username}</td><td><button className="hunt-link" onClick={() => onInvestigate?.(event.source_ip)}>{event.source_ip}</button></td><td><span className={`hunt-result-tag ${event.status}`}>{event.status}</span><small>{event.event_type}</small></td><td className="hunt-related">{alerts.map((alert) => <button key={`a${alert.id}`} onClick={() => onNavigate?.("alerts")}>{alert.title} <b>{alert.severity}</b></button>)}{incidents.map((incident) => <button key={`i${incident.id}`} onClick={() => onOpenIncident?.(incident.id)}>{incident.title} <b>INCIDENT</b></button>)}{!alerts.length && !incidents.length && <span className="hunt-no-links">No linked records</span>}</td></tr>)}</tbody></table></div>}
          {!loading && results && !results.results.length && <EmptyState className="hunt-state" title="No events match the current query and time range." />}
          {!results && !loading && <EmptyState className="hunt-empty" icon={<Search size={22} />} title="Ready to investigate" description="Choose a time range, add conditions and run a hunt." />}
          {results && <Pagination className="hunt-pagination" total={results.total} offset={offset} limit={results.limit} loading={loading} onOffsetChange={runHunt} />}
        </section>
        <div className="hunt-notice"><strong>Scope:</strong> results are based on locally stored event and relationship records. The query does not execute SQL or arbitrary commands. Empty severity means no related alert record is present.</div>
      </div>
    </div>
  </section>;
}
