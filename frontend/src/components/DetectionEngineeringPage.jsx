import { useCallback, useEffect, useRef, useState } from "react";
import { AlertTriangle, Beaker, Check, Clock3, History, Pencil, Plus, RefreshCw, Save, ShieldAlert, ToggleLeft, ToggleRight, X } from "lucide-react";

import { apiRequest, formatDate } from "../api";
import Dialog from "./ui/Dialog";

const emptyDraft = {
  name: "",
  description: "",
  aggregation: "failed_per_source_ip",
  threshold: 5,
  window_minutes: 10,
  severity: "medium",
  enabled: true,
  change_note: "",
};

const aggregations = [
  ["failed_per_source_ip", "Failed attempts from one source IP"],
  ["failed_per_username", "Failed attempts for one username"],
  ["distinct_users_per_source_ip", "Distinct usernames targeted from one source IP"],
  ["distinct_ips_per_username", "Distinct source IPs targeting one username"],
];

function aggregationName(key) {
  return aggregations.find(([value]) => value === key)?.[1] ?? key;
}

export default function DetectionEngineeringPage({ onError, onSuccess }) {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingId, setEditingId] = useState(null);
  const [draft, setDraft] = useState(emptyDraft);
  const [preview, setPreview] = useState(null);
  const [previewing, setPreviewing] = useState(false);
  const [versionsFor, setVersionsFor] = useState(null);
  const [versions, setVersions] = useState([]);
  const ruleNameRef = useRef(null);

  const loadRules = useCallback(async () => {
    setLoading(true);
    try {
      setRules(await apiRequest("/api/detection/rules"));
    } catch (error) {
      onError?.(`Detection rules could not be loaded: ${error.message}`);
    } finally {
      setLoading(false);
    }
  }, [onError]);

  useEffect(() => { loadRules(); }, [loadRules]);

  function startCreate() {
    setEditingId(null);
    setDraft(emptyDraft);
    setPreview(null);
    setEditorOpen(true);
  }

  function startEdit(rule) {
    setEditingId(rule.id);
    setDraft({ ...rule, change_note: "" });
    setPreview(null);
    setEditorOpen(true);
  }

  async function saveRule(event) {
    event.preventDefault();
    setSaving(true);
    try {
      await apiRequest(editingId ? `/api/detection/rules/${editingId}` : "/api/detection/rules", {
        method: editingId ? "PATCH" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(draft),
      });
      setEditorOpen(false);
      setPreview(null);
      onSuccess?.(editingId ? "Rule updated. New version recorded." : "Rule created as version 1.");
      await loadRules();
    } catch (error) {
      onError?.(`Rule could not be saved: ${error.message}`);
    } finally {
      setSaving(false);
    }
  }

  async function previewDraft() {
    setPreviewing(true);
    try {
      const result = await apiRequest("/api/detection/rules/preview?window_hours=168", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(draft),
      });
      setPreview(result);
    } catch (error) {
      onError?.(`Rule preview failed: ${error.message}`);
    } finally {
      setPreviewing(false);
    }
  }

  async function previewSaved(rule) {
    try {
      const result = await apiRequest(`/api/detection/rules/${rule.id}/preview?window_hours=168`, { method: "POST" });
      setPreview(result);
      setEditorOpen(false);
    } catch (error) {
      onError?.(`Rule preview failed: ${error.message}`);
    }
  }

  async function toggleRule(rule) {
    try {
      await apiRequest(`/api/detection/rules/${rule.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !rule.enabled, change_note: rule.enabled ? "Disabled by analyst" : "Enabled by analyst" }),
      });
      onSuccess?.(rule.enabled ? "Rule disabled." : "Rule enabled for new events.");
      await loadRules();
    } catch (error) {
      onError?.(`Rule state could not be changed: ${error.message}`);
    }
  }

  async function showVersions(rule) {
    if (versionsFor === rule.id) {
      setVersionsFor(null);
      setVersions([]);
      return;
    }
    try {
      setVersions(await apiRequest(`/api/detection/rules/${rule.id}/versions`));
      setVersionsFor(rule.id);
    } catch (error) {
      onError?.(`Rule history could not be loaded: ${error.message}`);
    }
  }

  const activeCount = rules.filter((rule) => rule.enabled).length;
  const versionCount = rules.reduce((sum, rule) => sum + rule.current_version, 0);

  return (
    <div className="page-content">
      <div className="page-heading">
        <div><div className="eyebrow"><ShieldAlert size={13} />DETECTION OPERATIONS <span className="heading-divider">/</span> RULE LIFECYCLE</div><h1>Detection Engineering</h1><p>Create bounded authentication rules, preview their impact against stored events, and track each configuration revision.</p></div>
        <button className="button primary" onClick={startCreate}><Plus size={14} />New rule</button>
      </div>

      <div className="metric-strip detection-rule-metrics">
        <div className="metric-cell"><div className="metric-top"><span className="metric-icon"><ShieldAlert size={14} /></span><span className="metric-meta">CUSTOM RULES</span></div><strong className="metric-value">{rules.length}</strong><span className="metric-label">Locally managed</span></div>
        <div className="metric-cell"><div className="metric-top"><span className="metric-icon"><Check size={14} /></span><span className="metric-meta">ENABLED</span></div><strong className="metric-value">{activeCount}</strong><span className="metric-label">Evaluate new ingested failures</span></div>
        <div className="metric-cell"><div className="metric-top"><span className="metric-icon"><History size={14} /></span><span className="metric-meta">VERSIONS</span></div><strong className="metric-value">{versionCount}</strong><span className="metric-label">Append-only snapshots</span></div>
      </div>

      <section className="panel detection-rules-panel">
        <div className="panel-heading"><div><div className="section-kicker">AUTHENTICATION RULE LIBRARY</div><h2>Analyst managed rules</h2><p>Rules use a constrained aggregation over failed authentication events. Changes apply to newly ingested events.</p></div><button className="button secondary small-button" onClick={loadRules} disabled={loading}><RefreshCw size={12} className={loading ? "spin-icon" : ""} />Refresh</button></div>
        {loading ? <div className="empty-inline">Loading detection rules…</div> : rules.length === 0 ? <div className="empty-state"><span className="empty-icon"><ShieldAlert size={16} /></span><strong>No custom rules yet</strong><span>Create a rule and preview it against the locally stored event sample.</span></div> : <div className="detection-rule-list">{rules.map((rule) => <article className={`detection-rule-card ${rule.enabled ? "" : "disabled"}`} key={rule.id}>
          <div className="detection-rule-main"><div className="detection-rule-title"><span className={`severity-marker ${rule.severity}`} /><div><h3>{rule.name}</h3><p>{rule.description || aggregationName(rule.aggregation)}</p></div></div><span className={`rule-state ${rule.enabled ? "on" : "off"}`}>{rule.enabled ? "ENABLED" : "DISABLED"}</span></div>
          <div className="detection-rule-meta"><span>{aggregationName(rule.aggregation)}</span><span>Threshold <strong>{rule.threshold}</strong></span><span>Window <strong>{rule.window_minutes}m</strong></span><span>Version <strong>v{rule.current_version}</strong></span></div>
          <div className="detection-rule-actions"><button className="button secondary small-button" onClick={() => previewSaved(rule)}><Beaker size={12} />Preview</button><button className="button secondary small-button" onClick={() => startEdit(rule)}><Pencil size={12} />Edit</button><button className="button secondary small-button" onClick={() => showVersions(rule)}><History size={12} />History</button><button className="button quiet small-button" onClick={() => toggleRule(rule)}>{rule.enabled ? <ToggleRight size={14} /> : <ToggleLeft size={14} />}{rule.enabled ? "Disable" : "Enable"}</button></div>
          {versionsFor === rule.id && <div className="rule-version-list"><div className="section-kicker">APPEND-ONLY CONFIGURATION HISTORY</div>{versions.map((version) => <div className="rule-version-row" key={version.id}><div><strong>Version {version.version}</strong><span>{version.change_note || "Configuration saved"}</span></div><time>{formatDate(version.created_at)}</time><details><summary>Config</summary><code>{JSON.stringify(version.configuration, null, 2)}</code></details></div>)}</div>}
        </article>)}</div>}
      </section>

      <Dialog open={editorOpen} onClose={() => setEditorOpen(false)} className="rule-editor-backdrop" dialogClassName="panel rule-editor" labelledBy="rule-editor-title" initialFocusRef={ruleNameRef}>
        <div className="panel-heading"><div><div className="section-kicker">{editingId ? `EDIT RULE · VERSION ${rules.find((rule) => rule.id === editingId)?.current_version + 1}` : "NEW VERSIONED RULE"}</div><h2 id="rule-editor-title">{editingId ? "Rule configuration" : "Create detection rule"}</h2><p>Evaluation is limited to authentication failures in a configured time window.</p></div><button className="icon-quiet" onClick={() => setEditorOpen(false)} aria-label="Close rule editor"><X size={15} /></button></div>
        <form onSubmit={saveRule} className="rule-form">
          <label>Rule name<input ref={ruleNameRef} required minLength="3" maxLength="120" value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} placeholder="Repeated failures by account" /></label>
          <label>Description<textarea maxLength="500" rows="2" value={draft.description} onChange={(event) => setDraft({ ...draft, description: event.target.value })} placeholder="What should the analyst review?" /></label>
          <label>Aggregation<select value={draft.aggregation} onChange={(event) => setDraft({ ...draft, aggregation: event.target.value })}>{aggregations.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
          <div className="rule-form-pair"><label>Threshold<input type="number" min="2" max="500" required value={draft.threshold} onChange={(event) => setDraft({ ...draft, threshold: Number(event.target.value) })} /></label><label>Window (minutes)<input type="number" min="1" max="1440" required value={draft.window_minutes} onChange={(event) => setDraft({ ...draft, window_minutes: Number(event.target.value) })} /></label></div>
          <div className="rule-form-pair"><label>Severity<select value={draft.severity} onChange={(event) => setDraft({ ...draft, severity: event.target.value })}>{["critical", "high", "medium", "low"].map((severity) => <option key={severity}>{severity}</option>)}</select></label><label>Change note<input maxLength="500" value={draft.change_note} onChange={(event) => setDraft({ ...draft, change_note: event.target.value })} placeholder="Why is this being changed?" /></label></div>
          <label className="rule-enabled-toggle"><input type="checkbox" checked={draft.enabled} onChange={(event) => setDraft({ ...draft, enabled: event.target.checked })} />Evaluate this rule on new events</label>
          <div className="rule-form-actions"><button type="button" className="button secondary" onClick={previewDraft} disabled={previewing}><Beaker size={13} />{previewing ? "Previewing…" : "Preview impact"}</button><span /><button type="button" className="button secondary" onClick={() => setEditorOpen(false)}>Cancel</button><button className="button primary" disabled={saving}><Save size={13} />{saving ? "Saving…" : "Save version"}</button></div>
        </form>
      </Dialog>

      {preview && <section className="panel detection-preview-panel"><div className="panel-heading"><div><div className="section-kicker">READ-ONLY PREVIEW · PREVIOUS 7 DAYS</div><h2>Candidate groups in stored events</h2><p>{preview.events_analyzed.toLocaleString()} failed authentication events analyzed{preview.truncated ? " · sample capped at 5,000" : ""}</p></div><button className="icon-quiet" onClick={() => setPreview(null)} aria-label="Close preview"><X size={14} /></button></div><div className="detection-preview-summary"><div><span>Candidate groups</span><strong>{preview.candidate_count}</strong></div><div><span>Event groups returned</span><strong>{preview.matched_groups.length}</strong></div><div><span>Data written</span><strong>None</strong></div></div><div className="detection-quality-table-wrap" role="region" aria-label="Detection rule preview evidence table. Scroll horizontally to view all columns." tabIndex={0}><table className="data-table"><thead><tr><th>GROUP</th><th>OBSERVED</th><th>SOURCE IP</th><th>USERNAMES</th><th>EVENT IDS</th></tr></thead><tbody>{preview.matched_groups.map((group) => <tr key={group.match_key}><td>{group.match_key}</td><td>{group.observed_value}</td><td>{group.source_ip}</td><td>{group.usernames.join(", ")}</td><td>{group.event_ids.join(", ")}</td></tr>)}{preview.matched_groups.length === 0 && <tr><td colSpan="5"><div className="empty-inline"><Clock3 size={13} />No groups met this configuration in the selected stored sample.</div></td></tr>}</tbody></table></div><small className="detection-quality-notice"><AlertTriangle size={12} />{preview.notice}</small></section>}

      <div className="model-notice"><AlertTriangle size={14} /><span>Built-in detections remain active under Detection Settings. Custom rules in this phase cover failed authentication events only; preview never creates alerts, and generated alerts are review signals rather than confirmed attacks.</span></div>
    </div>
  );
}
