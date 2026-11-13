import { useCallback, useEffect, useState } from "react";
import { Activity, RefreshCw, ShieldAlert, ShieldCheck } from "lucide-react";

import { apiRequest, formatDate } from "../api";

export default function AuditPage({ onError }) {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [entityType, setEntityType] = useState("");
  const [integrity, setIntegrity] = useState(null);
  const [checkingIntegrity, setCheckingIntegrity] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const query = new URLSearchParams({ limit: "200" });
      if (entityType) query.set("entity_type", entityType);
      setEntries(await apiRequest(`/api/audit?${query}`));
    } catch (error) {
      onError(error.message);
    } finally {
      setLoading(false);
    }
  }, [entityType, onError]);

  const loadIntegrity = useCallback(async () => {
    setCheckingIntegrity(true);
    try {
      setIntegrity(await apiRequest("/api/audit/integrity"));
    } catch (error) {
      setIntegrity(null);
      onError(error.message);
    } finally {
      setCheckingIntegrity(false);
    }
  }, [onError]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { loadIntegrity(); }, [loadIntegrity]);

  function refreshAll() {
    load();
    loadIntegrity();
  }

  return (
    <div className="page-content">
      <div className="page-heading"><div><div className="eyebrow"><Activity size={13} />WORKSPACE HISTORY</div><h1>Audit history</h1><p>Recent analyst actions and data changes recorded by this local workspace.</p></div><button className="button secondary" onClick={refreshAll} disabled={loading || checkingIntegrity}><RefreshCw size={13} className={loading || checkingIntegrity ? "spin-icon" : ""} />Refresh</button></div>
      <section className={`panel audit-integrity-panel ${integrity?.valid ? "verified" : integrity ? "failed" : "checking"}`} role="status"><div className="audit-integrity-icon">{integrity?.valid ? <ShieldCheck size={18} /> : <ShieldAlert size={18} />}</div><div className="audit-integrity-copy"><strong>{checkingIntegrity ? "Verifying audit chain…" : integrity?.valid ? "Audit chain verified" : integrity ? "Audit integrity check failed" : "Audit integrity unavailable"}</strong><span>{checkingIntegrity ? "Checking entry order, SHA-256 hashes, and stored chain head." : integrity?.message ?? "The integrity service could not be reached."}</span>{integrity?.first_invalid_entry_id && <small>First invalid entry: #{integrity.first_invalid_entry_id}</small>}</div><div className="audit-integrity-head"><span>{integrity?.checked_entries ?? 0} entries checked</span>{integrity?.head_hash && <code title={integrity.head_hash}>HEAD {integrity.head_hash.slice(0, 16)}…</code>}</div></section>
      <section className="panel">
        <div className="audit-toolbar"><div><strong>Recorded activity</strong><span>{entries.length} recent entries</span></div><label className="select-field"><select value={entityType} onChange={(event) => setEntityType(event.target.value)} aria-label="Filter audit history by record type"><option value="">All record types</option><option value="auth_event">Authentication events</option><option value="alert">Alerts</option><option value="incident">Incidents</option><option value="settings">Settings</option><option value="indicator">IP indicators</option><option value="saved_filter">Saved filters</option><option value="ingestion_source">Ingestion sources</option></select></label></div>
        {loading ? <div className="table-loading"><span className="status-pulse" />Loading audit history…</div> : entries.length ? <div className="table-wrap" role="region" aria-label="Audit history table. Scroll horizontally to inspect all evidence fields." tabIndex={0}><table className="data-table audit-table"><thead><tr><th>TIME</th><th>ACTOR</th><th>ACTION</th><th>RECORD</th><th>DETAILS</th><th>CHAIN HASH</th></tr></thead><tbody>{entries.map((entry) => <tr key={entry.id}><td><time dateTime={entry.created_at}>{formatDate(entry.created_at)}</time></td><td>{entry.actor}</td><td><code>{entry.action}</code></td><td>{entry.entity_type}{entry.entity_id ? ` #${entry.entity_id}` : ""}</td><td className="audit-detail">{Object.entries(entry.details ?? {}).map(([key, value]) => `${key}: ${value}`).join(" · ") || "—"}</td><td><code className="audit-hash" title={entry.entry_hash}>{entry.entry_hash.slice(0, 12)}…</code></td></tr>)}</tbody></table></div> : <div className="empty-state"><div className="empty-icon"><Activity size={16} /></div><strong>No recorded activity</strong><span>Workspace changes will appear here.</span></div>}
      </section>
      <div className="page-note">SQLite blocks ordinary audit-entry edits and deletions; the SHA-256 chain makes tampering detectable. The chain head is stored in this same local database, so production deployments should export and anchor it in independent secure storage. Collector actions include the source identity; analyst UI activity is labeled “Local analyst”.</div>
    </div>
  );
}
