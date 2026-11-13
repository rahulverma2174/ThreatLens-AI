import { useCallback, useEffect, useMemo, useState } from "react";
import { Activity, Fingerprint, Pencil, Search, ShieldAlert, Trash2, Clock3 } from "lucide-react";

import { apiRequest, formatDate } from "../api";
import { EventsTable } from "./EventsTable";

export default function InvestigationPage({ initialIP = "", alerts, onError, onSuccess }) {
  const defaultExpiry = () => { const date = new Date(Date.now() + 7 * 86400000); date.setMinutes(date.getMinutes() - date.getTimezoneOffset()); return date.toISOString().slice(0, 16); };
  const [ip, setIp] = useState(initialIP);
  const [result, setResult] = useState(null);
  const [indicators, setIndicators] = useState([]);
  const [indicatorAddress, setIndicatorAddress] = useState(initialIP);
  const [editingIndicatorId, setEditingIndicatorId] = useState(null);
  const [indicatorKind, setIndicatorKind] = useState("blocklist");
  const [indicatorType, setIndicatorType] = useState("ip");
  const [indicatorNote, setIndicatorNote] = useState("");
  const [indicatorConfidence, setIndicatorConfidence] = useState(50);
  const [indicatorSource, setIndicatorSource] = useState("Local analyst");
  const [indicatorExpiry, setIndicatorExpiry] = useState(defaultExpiry);
  const [loading, setLoading] = useState(false);
  const [savingIndicator, setSavingIndicator] = useState(false);
  const [searched, setSearched] = useState(false);
  const [exceptions, setExceptions] = useState([]);
  const [exceptionIP, setExceptionIP] = useState(initialIP);
  const [exceptionUsername, setExceptionUsername] = useState("");
  const [exceptionRule, setExceptionRule] = useState("");
  const [exceptionReason, setExceptionReason] = useState("");
  const [exceptionExpiry, setExceptionExpiry] = useState(defaultExpiry);
  const activeIndicator = result ? indicators.find((item) => item.indicator_type === "ip" && item.value === result.source_ip) : null;
  const matchingAlerts = useMemo(() => result ? alerts.filter((alert) => alert.source_ip === result.source_ip) : [], [alerts, result]);
  const refreshIndicators = useCallback(async () => {
    try {
      const [localIndicators, localExceptions] = await Promise.all([
        apiRequest("/api/intelligence/indicators"), apiRequest("/api/detection/exceptions"),
      ]);
      setIndicators(localIndicators);
      setExceptions(localExceptions);
    }
    catch (error) { onError(error.message); }
  }, [onError]);

  async function addException(event) {
    event.preventDefault();
    try {
      const item = await apiRequest("/api/detection/exceptions", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source_ip: exceptionIP.trim() || null, username: exceptionUsername.trim() || null, detection_key: exceptionRule || null, reason: exceptionReason.trim(), expires_at: new Date(exceptionExpiry).toISOString() }),
      });
      setExceptions((current) => [item, ...current]);
      setExceptionReason("");
      onSuccess("Time-limited detection exception added.");
    } catch (error) { onError(error.message); }
  }

  async function removeException(item) {
    try {
      await apiRequest(`/api/detection/exceptions/${item.id}`, { method: "DELETE" });
      setExceptions((current) => current.filter((entry) => entry.id !== item.id));
      onSuccess("Detection exception removed.");
    } catch (error) { onError(error.message); }
  }
  const investigate = useCallback(async (address) => {
    if (!address.trim()) return;
    setIp(address.trim());
    setIndicatorAddress(address.trim());
    setLoading(true);
    setSearched(true);
    try { setResult(await apiRequest(`/api/investigation/${encodeURIComponent(address.trim())}`)); }
    catch (error) { setResult(null); onError(error.message); }
    finally { setLoading(false); }
  }, [onError]);

  useEffect(() => { refreshIndicators(); }, [refreshIndicators]);
  useEffect(() => {
    if (!initialIP) return;
    setIp(initialIP);
    investigate(initialIP);
  }, [initialIP, investigate]);

  useEffect(() => {
    setIndicatorKind(activeIndicator?.kind ?? "blocklist");
    setIndicatorNote(activeIndicator?.note ?? "");
    setIndicatorType(activeIndicator?.indicator_type ?? "ip");
    setIndicatorConfidence(activeIndicator?.confidence ?? 50);
    setIndicatorSource(activeIndicator?.source ?? "Local analyst");
    setIndicatorExpiry(activeIndicator?.expires_at ? new Date(new Date(activeIndicator.expires_at).getTime() - new Date(activeIndicator.expires_at).getTimezoneOffset() * 60000).toISOString().slice(0, 16) : defaultExpiry());
  }, [activeIndicator?.id, activeIndicator?.kind, activeIndicator?.note, result?.source_ip]);

  async function saveIndicator(event) {
    event.preventDefault();
    if (!indicatorAddress.trim()) return;
    setSavingIndicator(true);
    try {
      const payload = { indicator_type: indicatorType, value: indicatorAddress.trim(), source_ip: indicatorType === "ip" ? indicatorAddress.trim() : null, kind: indicatorKind, note: indicatorNote, confidence: Number(indicatorConfidence), source: indicatorSource, expires_at: indicatorExpiry ? new Date(indicatorExpiry).toISOString() : null };
      const saved = await apiRequest(
        editingIndicatorId
          ? `/api/intelligence/indicators/${editingIndicatorId}`
          : "/api/intelligence/indicators",
        {
          method: editingIndicatorId ? "PUT" : "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        },
      );
      setIndicators((current) => [...current.filter((item) => item.id !== saved.id && item.value !== saved.value), saved]);
      setEditingIndicatorId(saved.id);
      onSuccess(editingIndicatorId ? "Local IP indicator updated." : "Local IP indicator added.");
    } catch (error) {
      onError(error.message);
    } finally {
      setSavingIndicator(false);
    }
  }

  async function removeIndicator(indicator) {
    if (!window.confirm(`Remove the local indicator for ${indicator.value}?`)) return;
    try {
      await apiRequest(`/api/intelligence/indicators/${indicator.id}`, { method: "DELETE" });
      setIndicators((current) => current.filter((item) => item.id !== indicator.id));
      if (editingIndicatorId === indicator.id) {
        setEditingIndicatorId(null);
        setIndicatorAddress("");
        setIndicatorKind("blocklist");
        setIndicatorNote("");
      }
      onSuccess("Local IP indicator removed.");
    } catch (error) {
      onError(error.message);
    }
  }

  return (
    <div className="page-content ip-page">
      <div className="page-heading"><div><div className="eyebrow"><Fingerprint size={13} />IP INTELLIGENCE <span className="heading-divider">/</span> LOCAL TELEMETRY</div><h1>IP intelligence</h1><p>Build an investigation from observed local authentication events. No external reputation data is queried.</p></div></div>
      <section className="ip-search-strip"><div className="ip-search-icon"><Fingerprint size={19} /></div><div className="ip-search-copy"><strong>Investigate a source address</strong><span>Review activity, targeted identities, and matching local detection signals.</span></div><form onSubmit={(event) => { event.preventDefault(); investigate(ip); }}><label className="search-field"><Search size={14} /><input value={ip} onChange={(event) => setIp(event.target.value)} placeholder="IPv4 or IPv6 address" aria-label="Source IP address" /></label><button className="button primary" disabled={loading}>{loading ? "Analyzing…" : "Analyze IP"}</button></form></section>
      {result ? <>
        <div className="ip-identity-bar"><div><span className="section-kicker">SOURCE ADDRESS</span><h2><code>{result.source_ip}</code></h2></div><div className="ip-observation-tag"><span className={`risk-indicator ${matchingAlerts.some((alert) => ["critical", "high"].includes(alert.severity) && alert.status !== "resolved") ? "danger" : result.failed_logins ? "caution" : "healthy"}`} />{matchingAlerts.some((alert) => ["critical", "high"].includes(alert.severity) && alert.status !== "resolved") ? "Elevated local risk" : result.failed_logins ? "Failed activity observed" : "No failed activity observed"}</div>{activeIndicator && <span className={`indicator-badge ${activeIndicator.kind}`}>{activeIndicator.kind} · local</span>}</div>
        <div className="ip-facts-strip">{[["Observed events", result.total_events, "EVENTS"], ["Failed logins", result.failed_logins, "FAILURES"], ["Successful logins", result.successful_logins, "SUCCESSES"], ["Targeted identities", result.usernames.length, "ACCOUNTS"], ["Detection signals", matchingAlerts.length, "LOCAL RULES"]].map(([label, value, meta], index) => <div className={`ip-fact ${index === 1 && value ? "fact-danger" : ""}`} key={label}><span>{meta}</span><strong>{value.toLocaleString()}</strong><small>{label}</small></div>)}</div>
        <div className="ip-analysis-grid">
          <section className="panel ip-user-panel"><div className="panel-heading"><div><div className="section-kicker">IDENTITY EXPOSURE</div><h2>Targeted usernames</h2><p>Account names present in this local event history</p></div><span className="counter-chip">{result.usernames.length}</span></div><div className="username-tags">{result.usernames.map((username) => <span key={username}>{username}</span>)}{!result.usernames.length && <span className="muted-cell">No observed usernames</span>}</div></section>
          <section className="panel ip-risk-panel"><div className="panel-heading"><div><div className="section-kicker">DETECTION CONTEXT</div><h2>Risk indicators</h2><p>Signals are limited to locally observed evidence</p></div><ShieldAlert size={16} className="panel-icon" /></div><div className="risk-indicator-list"><div><i className={result.failed_logins >= 5 ? "indicator-danger" : result.failed_logins ? "indicator-warn" : "indicator-ok"} /><span><strong>{result.failed_logins >= 5 ? "Repeated authentication failures" : result.failed_logins ? "Failed login attempts" : "No failed logins observed"}</strong><small>{result.failed_logins} failure records in stored history</small></span></div><div><i className={matchingAlerts.length ? "indicator-danger" : "indicator-ok"} /><span><strong>{matchingAlerts.length ? `${matchingAlerts.length} linked detection signal${matchingAlerts.length === 1 ? "" : "s"}` : "No linked rule detections"}</strong><small>Based on generated local authentication rules</small></span></div><div><i className="indicator-neutral" /><span><strong>Private reputation not assessed</strong><small>External enrichment is not configured for this local project</small></span></div></div></section>
        </div>
        {matchingAlerts.length > 0 && <section className="panel ip-detections"><div className="panel-heading"><div><div className="section-kicker">LINKED DETECTIONS</div><h2>Rules triggered by this source</h2></div></div>{matchingAlerts.map((alert) => <div className="ip-alert-row" key={alert.id}><span className={`severity-marker ${alert.severity}`} /><span><strong>{alert.title}</strong><small>{alert.reason}</small></span><span className={`status-mini ${alert.status}`}>{alert.status}</span></div>)}</section>}
        <section className="panel ip-timeline-panel"><div className="panel-heading"><div><div className="section-kicker">OBSERVED AUTHENTICATION</div><h2>Activity timeline</h2><p>{result.total_events} events · most recent first · {result.events.length} shown</p></div><Activity size={16} className="panel-icon" /></div><EventsTable events={result.events} alerts={matchingAlerts} /><div className="ip-timeline-foot">Local event records from {formatDate(result.events.at(-1)?.timestamp)} through {formatDate(result.events[0]?.timestamp)}.</div></section>
      </> : searched && !loading ? <div className="empty-panel ip-empty"><div className="empty-icon"><Fingerprint size={17} /></div><strong>No local activity found</strong><span>No authentication records were found for this source address.</span></div> : <div className="ip-empty-hint"><Activity size={15} />Enter an IP address to query the local event store.</div>}
      <section className="panel ip-indicator-panel"><div className="panel-heading"><div><div className="section-kicker">LOCAL THREAT INDICATORS</div><h2>IOC management</h2><p>Local provenance, confidence, expiry, and event correlation; no external reputation is implied.</p></div><span className="local-only">LOCAL ONLY</span></div><form className="indicator-form ioc-form" onSubmit={saveIndicator}><label className="select-field"><select value={indicatorType} onChange={(event) => setIndicatorType(event.target.value)} aria-label="Indicator value type"><option value="ip">IP address</option><option value="domain">Domain</option><option value="hash">File hash</option></select></label><input className="indicator-address" value={indicatorAddress} onChange={(event) => setIndicatorAddress(event.target.value)} placeholder={indicatorType === "ip" ? "IPv4 or IPv6 address" : indicatorType === "domain" ? "example.org" : "MD5, SHA-1, or SHA-256"} aria-label="Indicator value" required /><label className="select-field"><select value={indicatorKind} onChange={(event) => setIndicatorKind(event.target.value)} aria-label="Local analyst disposition"><option value="blocklist">Watch / blocklist</option><option value="allowlist">Allowlist</option></select></label><input type="number" min="0" max="100" value={indicatorConfidence} onChange={(event) => setIndicatorConfidence(event.target.value)} aria-label="Indicator confidence" title="Analyst-assigned confidence, 0 to 100" /><input value={indicatorSource} onChange={(event) => setIndicatorSource(event.target.value)} maxLength={160} placeholder="Source / provenance" aria-label="Indicator source" required /><input type="datetime-local" value={indicatorExpiry} onChange={(event) => setIndicatorExpiry(event.target.value)} aria-label="Indicator expiry" /><input value={indicatorNote} onChange={(event) => setIndicatorNote(event.target.value)} maxLength={500} placeholder="Analyst note" aria-label="Indicator analyst note" /><button className="button primary" disabled={savingIndicator}>{savingIndicator ? "Saving…" : editingIndicatorId ? "Update IOC" : "Add IOC"}</button>{editingIndicatorId && <button className="button secondary" type="button" onClick={() => { setEditingIndicatorId(null); setIndicatorAddress(""); setIndicatorKind("blocklist"); setIndicatorNote(""); setIndicatorType("ip"); setIndicatorConfidence(50); setIndicatorSource("Local analyst"); setIndicatorExpiry(defaultExpiry()); }}>Clear</button>}</form><div className="indicator-list ioc-list">{indicators.map((indicator) => <article className={`indicator-list-row ${editingIndicatorId === indicator.id ? "selected" : ""}`} key={indicator.id}><span className={`indicator-badge ${indicator.kind}`}>{indicator.indicator_type} · {indicator.kind}</span><code>{indicator.value}</code><span className="indicator-note">{indicator.note || "No analyst note"}<small>{indicator.source} · confidence {indicator.confidence}% · {indicator.matching_event_count} local events{indicator.expires_at ? ` · expires ${formatDate(indicator.expires_at)}` : " · no expiry"}</small></span><small>{formatDate(indicator.updated_at)}</small><button className="icon-quiet" onClick={() => { setEditingIndicatorId(indicator.id); setIndicatorAddress(indicator.value); setIndicatorKind(indicator.kind); setIndicatorNote(indicator.note); setIndicatorType(indicator.indicator_type); setIndicatorConfidence(indicator.confidence); setIndicatorSource(indicator.source); setIndicatorExpiry(indicator.expires_at ? new Date(new Date(indicator.expires_at).getTime() - new Date(indicator.expires_at).getTimezoneOffset() * 60000).toISOString().slice(0, 16) : ""); }} aria-label={`Edit ${indicator.value}`}><Pencil size={12} /></button>{indicator.indicator_type === "ip" && <button className="icon-quiet" onClick={() => investigate(indicator.value)} aria-label={`Investigate ${indicator.value}`}><Search size={12} /></button>}<button className="icon-quiet" onClick={() => removeIndicator(indicator)} aria-label={`Remove ${indicator.value}`}><Trash2 size={12} /></button></article>)}{!indicators.length && <div className="empty-inline">No local indicators have been added.</div>}</div><div className="relationship-footnote">IOC matches against locally stored events are shown for IP values only. Domain and hash entries remain analyst-managed until those values exist in an event source. Entries never automatically block traffic.</div></section>
      <section className="panel exception-panel"><div className="panel-heading"><div><div className="section-kicker">DETECTION NOISE CONTROL</div><h2>Time-limited rule exceptions</h2><p>Exceptions suppress matching future signals until expiry; existing alerts are retained.</p></div><Clock3 size={16} className="panel-icon" /></div><form className="exception-form" onSubmit={addException}><input value={exceptionIP} onChange={(event) => setExceptionIP(event.target.value)} placeholder="Source IP (optional)" aria-label="Exception source IP" /><input value={exceptionUsername} onChange={(event) => setExceptionUsername(event.target.value)} placeholder="Username (optional)" aria-label="Exception username" /><select value={exceptionRule} onChange={(event) => setExceptionRule(event.target.value)} aria-label="Detection rule scope"><option value="">All detection rules</option><option value="repeated_failures">Repeated failures</option><option value="brute_force">Brute force</option><option value="login_burst">Login burst</option><option value="multiple_usernames">Multiple usernames</option><option value="multiple_source_ips_account">Account across IPs</option><option value="success_after_failures">Success after failures</option></select><input value={exceptionReason} onChange={(event) => setExceptionReason(event.target.value)} placeholder="Reason for exception" aria-label="Exception reason" required minLength={3} maxLength={500} /><label>Expires<input type="datetime-local" value={exceptionExpiry} onChange={(event) => setExceptionExpiry(event.target.value)} required /></label><button className="button primary" disabled={!exceptionIP.trim() && !exceptionUsername.trim()}>Add exception</button></form><div className="exception-list">{exceptions.map((item) => <article key={item.id} className={new Date(item.expires_at) <= new Date() ? "expired" : ""}><div><strong>{item.source_ip || item.username}</strong><span>{item.source_ip && item.username ? ` · ${item.username}` : ""}</span><small>{item.detection_key || "All rules"} · {item.reason}</small></div><time>{new Date(item.expires_at) <= new Date() ? "Expired" : `Expires ${formatDate(item.expires_at)}`}</time><button className="icon-quiet" onClick={() => removeException(item)} aria-label="Remove exception"><Trash2 size={13} /></button></article>)}{!exceptions.length && <div className="empty-inline">No detection exceptions configured.</div>}</div><div className="relationship-footnote">Match scope is limited to the selected IP or username and optional rule. Exceptions expire automatically and never delete existing detections.</div></section>
    </div>
  );
}
