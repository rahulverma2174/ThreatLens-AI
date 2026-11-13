import { useCallback, useEffect, useState } from "react";
import { Activity, FlaskConical, RefreshCw, Save, Settings2 } from "lucide-react";

import { apiRequest } from "../api";

const fields = [
  ["brute_force_threshold", "Brute-force threshold", "Failures from one IP before a high-priority alert."],
  ["window_minutes", "Detection window", "Time window used by authentication rules."],
  ["targeted_username_threshold", "Distinct usernames threshold", "Different usernames from one source before alerting."],
  ["repeated_failure_threshold", "Repeated failures threshold", "Minimum failed attempts for a repeated-failure signal."],
  ["success_after_failure_threshold", "Success-after-failure threshold", "Failures before a subsequent success is flagged."],
  ["distributed_failure_threshold", "Distributed failures threshold", "Failed attempts for one account across multiple source IPs before a later success is flagged."],
  ["distributed_source_ip_threshold", "Distinct source IP threshold", "Minimum number of different source IPs in that cross-IP sequence."],
];

export default function SettingsPage({ onError, onSuccess, canAdmin = true }) {
  const [settings, setSettings] = useState(null);
  const [saving, setSaving] = useState(false);
  const [syslog, setSyslog] = useState(null);
  const [loadingSyslog, setLoadingSyslog] = useState(false);
  const [replaying, setReplaying] = useState(false);
  const [replay, setReplay] = useState(null);

  const replayRows = replay
    ? [...new Set([...replay.current.rules, ...replay.proposed.rules].map((rule) => rule.detection_key))]
      .sort()
      .map((key) => ({
        key,
        current: replay.current.rules.find((rule) => rule.detection_key === key),
        proposed: replay.proposed.rules.find((rule) => rule.detection_key === key),
      }))
    : [];

  const loadSyslogStatus = useCallback(async () => {
    setLoadingSyslog(true);
    try {
      setSyslog(await apiRequest("/api/ingestion/syslog"));
    } catch (error) {
      onError(error.message);
    } finally {
      setLoadingSyslog(false);
    }
  }, [onError]);

  useEffect(() => {
    let active = true;
    apiRequest("/api/settings/detection").then((data) => { if (active) setSettings(data); }).catch((error) => onError(error.message));
    return () => { active = false; };
  }, [onError]);

  useEffect(() => { loadSyslogStatus(); }, [loadSyslogStatus]);
  function change(key, value) {
    setSettings((current) => ({ ...current, [key]: Number(value) }));
    setReplay(null);
  }

  async function preview(event) {
    event.preventDefault();
    if (!settings || replaying) return;
    setReplaying(true);
    try {
      setReplay(await apiRequest("/api/analytics/detection-replay", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ window_hours: 168, settings }),
      }));
    } catch (error) {
      onError(error.message);
    } finally {
      setReplaying(false);
    }
  }
  async function save(event) {
    event.preventDefault();
    if (!canAdmin) return;
    setSaving(true);
    try {
      const updated = await apiRequest("/api/settings/detection", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(settings) });
      setSettings(updated);
      setReplay(null);
      onSuccess("Detection settings saved.");
    } catch (error) {
      onError(error.message);
    } finally {
      setSaving(false);
    }
  }
  return (
    <div className="page-content">
      <div className="page-heading"><div><div className="eyebrow"><Settings2 size={13} />WORKSPACE CONFIGURATION</div><h1>Settings</h1><p>Configure local detection thresholds and monitoring behavior.</p></div></div>
      <form className="settings-form panel" onSubmit={save}>
        <div className="panel-heading"><div><div className="section-kicker">DETECTION CONFIGURATION</div><h2>Rule thresholds</h2><p>Changes apply to new ingested events and CSV/JSON imports.</p></div><span className="local-only">{canAdmin ? "ADMIN" : "READ ONLY"}</span></div>
        {settings && <label className="setting-row monitoring-toggle"><span className="setting-description"><strong>Threat monitoring</strong><small>Store events while pausing all rule-based alert generation.</small></span><input type="checkbox" checked={settings.monitoring_enabled} disabled={!canAdmin} onChange={(event) => { setSettings((current) => ({ ...current, monitoring_enabled: event.target.checked })); setReplay(null); }} /></label>}
        {settings && fields.map(([key, title, description]) => <label className="setting-row" key={key}><span className="setting-description"><strong>{title}</strong><small>{description}</small></span><span className="number-control"><input type="number" value={settings[key]} disabled={!canAdmin} min={key === "window_minutes" ? 1 : key === "brute_force_threshold" ? 3 : 2} max={key === "window_minutes" ? 1440 : key === "distributed_source_ip_threshold" ? 20 : 100} onChange={(event) => change(key, event.target.value)} /><span>{key === "window_minutes" ? "min" : "count"}</span></span></label>)}
        <div className="settings-actions"><span>Thresholds: 2–100 (brute-force: 3–100, time window: 1–1,440 min).</span><button type="button" className="button secondary" onClick={preview} disabled={!settings || replaying || saving}><FlaskConical size={14} />{replaying ? "Replaying events…" : "Preview impact"}</button><button className="button primary" disabled={!settings || saving || !canAdmin}><Save size={14} />{saving ? "Saving…" : "Save changes"}</button></div>
      </form>
      {replay && <section className="panel detection-replay-panel"><div className="panel-heading"><div><div className="section-kicker">READ-ONLY RULE SIMULATION</div><h2>Threshold impact preview</h2><p>{replay.events_analyzed.toLocaleString()} stored events · previous {replay.window_hours} hours{replay.truncated ? " · sample capped at 5,000" : ""}</p></div><span className="local-only">NO DATA WRITTEN</span></div><div className="replay-summary"><div><span>Current candidates</span><strong>{replay.current.total_candidates}</strong><small>{replay.current.total_suppressed} suppressed</small></div><div><span>Proposed candidates</span><strong>{replay.proposed.total_candidates}</strong><small>{replay.proposed.total_suppressed} suppressed</small></div><div><span>Net change</span><strong className={replay.proposed.total_candidates > replay.current.total_candidates ? "replay-increase" : replay.proposed.total_candidates < replay.current.total_candidates ? "replay-decrease" : ""}>{replay.proposed.total_candidates - replay.current.total_candidates > 0 ? "+" : ""}{replay.proposed.total_candidates - replay.current.total_candidates}</strong><small>grouped by rule and source IP</small></div></div><div className="detection-quality-table-wrap" role="region" aria-label="Threshold replay evidence table. Scroll horizontally to view all columns." tabIndex={0}><table className="data-table"><thead><tr><th>RULE</th><th>CURRENT</th><th>PROPOSED</th><th>CHANGE</th><th>SAMPLE EVIDENCE</th></tr></thead><tbody>{replayRows.map(({ key, current, proposed }) => { const currentCount = current?.candidate_count ?? 0; const proposedCount = proposed?.candidate_count ?? 0; const delta = proposedCount - currentCount; const sample = proposed ?? current; return <tr key={key}><td>{(sample?.title ?? key.replaceAll("_", " "))}</td><td>{currentCount} alerts · {current?.suppressed_count ?? 0} suppressed</td><td>{proposedCount} alerts · {proposed?.suppressed_count ?? 0} suppressed</td><td className={delta > 0 ? "replay-increase" : delta < 0 ? "replay-decrease" : ""}>{delta > 0 ? "+" : ""}{delta}</td><td><details className="replay-evidence"><summary>{sample?.sample_source_ips?.length ?? 0} source IP sample(s)</summary><code>{(sample?.sample_source_ips ?? []).join(", ") || "No source samples"}</code><small>Event IDs: {(sample?.sample_event_ids ?? []).join(", ") || "none"}</small></details></td></tr>; })}{!replayRows.length && <tr><td colSpan="5"><div className="empty-inline">No rule candidates matched this sample.</div></td></tr>}</tbody></table></div><small className="detection-quality-notice">{replay.notice}</small></section>}
      <section className="panel syslog-source-panel">
        <div className="panel-heading"><div><div className="section-kicker">LIVE AUTH LOGS</div><h2>Linux SSH · Syslog TCP</h2><p>Accepted and failed SSH authentication lines enter the same detection pipeline as API and CSV events.</p></div><button className="button secondary small-button" onClick={loadSyslogStatus} disabled={loadingSyslog}><RefreshCw size={12} className={loadingSyslog ? "spin-icon" : ""} />Refresh</button></div>
        <div className="syslog-state-row"><span className={`syslog-state-dot ${syslog?.running ? "online" : "offline"}`} /><strong>{syslog?.running ? "Listener running" : syslog?.enabled ? "Listener unavailable" : "Listener disabled"}</strong><code>{syslog ? `${syslog.host}:${syslog.port}/TCP` : "Loading status…"}</code><span>{syslog?.allowed_sources?.length ? `Allowed: ${syslog.allowed_sources.join(", ")}` : "No sender networks allowed"}</span></div>
        {syslog?.last_error && <div className="syslog-error">{syslog.last_error}</div>}
        {syslog && <div className="syslog-counter-grid">{[["received", "Messages received"], ["ingested", "SSH events stored"], ["ignored", "Other messages ignored"], ["rejected", "Connections rejected"]].map(([key, label]) => <div key={key}><strong>{syslog.counters[key].toLocaleString()}</strong><span>{label}</span></div>)}</div>}
        <div className="syslog-setup"><div><Activity size={13} /><strong>Forward SSH logs from this Linux host</strong></div><pre><code>{"# /etc/rsyslog.d/60-threatlens.conf\nif $programname == 'sshd' then action(type=\"omfwd\" target=\"127.0.0.1\" port=\"5514\" protocol=\"tcp\")"}</code></pre><small>Then restart rsyslog. Listener and sender allowlist are configured in backend/.env; restarting the API applies changes.</small></div>
        <div className="syslog-security-note">Bound to loopback by default and accepts only 127.0.0.1 / ::1. To receive remote logs, set an explicit trusted sender CIDR allowlist. TCP syslog is unencrypted; keep remote forwarding on a trusted private network or use a TLS terminator.</div>
      </section>
      <div className="model-notice"><Settings2 size={14} /><span>Rule thresholds are illustrative and should be tuned for the environment. Monitoring uses synthetic or authorized local data only.</span></div>
    </div>
  );
}
