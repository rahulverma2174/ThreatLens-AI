import { useCallback, useEffect, useState } from "react";
import { Copy, Download, KeyRound, Plus, RefreshCw, ShieldOff } from "lucide-react";

import { apiRequest, formatDate } from "../api";

export default function WindowsSourcesPanel({ onError, onSuccess }) {
  const [sources, setSources] = useState([]);
  const [name, setName] = useState("");
  const [newToken, setNewToken] = useState(null);
  const [busy, setBusy] = useState(false);

  const loadSources = useCallback(async () => {
    try {
      setSources(await apiRequest("/api/ingestion/sources"));
    } catch (error) {
      onError(error.message);
    }
  }, [onError]);

  useEffect(() => { loadSources(); }, [loadSources]);

  async function createSource(event) {
    event.preventDefault();
    const cleanName = name.trim();
    if (cleanName.length < 2) return;
    setBusy(true);
    try {
      const result = await apiRequest("/api/ingestion/sources", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: cleanName, platform: "windows_security" }),
      });
      setSources((current) => [result.source, ...current]);
      setNewToken({ sourceName: result.source.name, token: result.token, sourceId: result.source.id });
      setName("");
      onSuccess("Windows source created. Copy its token now; it is shown only once.");
    } catch (error) {
      onError(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function rotateToken(source) {
    if (!window.confirm(`Rotate the token for ${source.name}? Its current collector will stop until updated.`)) return;
    setBusy(true);
    try {
      const result = await apiRequest(`/api/ingestion/sources/${source.id}/rotate`, { method: "POST" });
      setSources((current) => current.map((item) => item.id === source.id ? result.source : item));
      setNewToken({ sourceName: result.source.name, token: result.token, sourceId: result.source.id });
      onSuccess("Source token rotated. Update the Windows collector with the new token.");
    } catch (error) {
      onError(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function toggleSource(source) {
    setBusy(true);
    try {
      const updated = await apiRequest(`/api/ingestion/sources/${source.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !source.enabled }),
      });
      setSources((current) => current.map((item) => item.id === source.id ? updated : item));
    } catch (error) {
      onError(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function revokeSource(source) {
    if (!window.confirm(`Revoke ${source.name}'s token permanently? You can create a replacement token later.`)) return;
    setBusy(true);
    try {
      const updated = await apiRequest(`/api/ingestion/sources/${source.id}`, { method: "DELETE" });
      setSources((current) => current.map((item) => item.id === source.id ? updated : item));
      if (newToken?.sourceId === source.id) setNewToken(null);
      onSuccess(`Token revoked for ${source.name}.`);
    } catch (error) {
      onError(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function copyToken() {
    try {
      await navigator.clipboard.writeText(newToken.token);
      onSuccess("One-time token copied to clipboard.");
    } catch {
      onError("Clipboard access failed. Select and copy the token manually.");
    }
  }

  return (
    <section className="panel windows-sources-panel">
      <div className="panel-heading">
        <div><div className="section-kicker">AUTHENTICATED COLLECTION</div><h2>Windows Security sources</h2><p>Collect remote Windows logons with a per-source bearer token and a resumable PowerShell agent.</p></div>
        <div className="windows-source-header-actions"><button className="button secondary small-button" onClick={loadSources}><RefreshCw size={12} />Refresh</button><a className="button secondary small-button" href="/api/ingestion/windows/agent.ps1" download><Download size={12} />Agent script</a></div>
      </div>
      <form className="windows-source-create" onSubmit={createSource}>
        <label className="search-field"><KeyRound size={13} /><input value={name} onChange={(event) => setName(event.target.value)} placeholder="Source name (e.g. analyst-lab-win11)" aria-label="Windows source name" minLength={2} maxLength={120} required /></label>
        <button className="button primary small-button" disabled={busy || name.trim().length < 2}><Plus size={13} />Create source token</button>
      </form>
      {newToken && <div className="one-time-token">
        <div><strong>One-time token · {newToken.sourceName}</strong><button className="button secondary small-button" onClick={copyToken}><Copy size={12} />Copy</button><button className="icon-quiet" onClick={() => setNewToken(null)} aria-label="Dismiss one-time token">×</button></div>
        <code>{newToken.token}</code>
        <pre><code>{".\\threatlens_windows_agent.ps1 -ApiBaseUrl 'http://THREATLENS_COLLECTOR:8001'"}</code></pre>
        <small>Run the script and paste the token at its secure prompt. Windows encrypts it for the current user profile. The API stores only a token hash.</small>
      </div>}
      <div className="windows-source-list">
        {sources.map((source) => {
          const online = source.enabled && source.last_seen_at && Date.now() - new Date(source.last_seen_at).getTime() < 90_000;
          return <article className={`windows-source-row ${source.enabled ? "" : "disabled"}`} key={source.id}>
          <span className={`syslog-state-dot ${online ? "online" : "offline"}`} />
          <div className="windows-source-main"><strong>{source.name}</strong><span>{online ? "Collector online" : source.enabled ? "Enabled · no recent heartbeat" : "Paused"} · {source.token_prefix ? `${source.token_prefix}…` : "token revoked"}</span></div>
          <div className="windows-source-stats"><strong>{source.events_ingested.toLocaleString()}</strong><small>events</small></div>
          <div className="windows-source-seen"><strong>{source.last_seen_at ? `Check-in ${formatDate(source.last_seen_at)}` : "Never connected"}</strong><small>{source.last_sender_ip || "No sender observed"} · last event {formatDate(source.last_event_at)} · {source.events_ignored} ignored · {source.events_duplicated} duplicates</small></div>
          <div className="windows-source-actions"><button className="button secondary small-button" onClick={() => toggleSource(source)} disabled={busy || !source.token_prefix}>{source.enabled ? "Pause" : "Resume"}</button><button className="icon-quiet" onClick={() => rotateToken(source)} disabled={busy} title="Rotate source token" aria-label={`Rotate ${source.name} token`}><RefreshCw size={13} /></button><button className="icon-quiet source-revoke" onClick={() => revokeSource(source)} disabled={busy || !source.token_prefix} title="Revoke source token" aria-label={`Revoke ${source.name} token`}><ShieldOff size={13} /></button></div>
          </article>;
        })}
        {!sources.length && <div className="empty-inline">No Windows sources registered yet. Create a token to connect the collector.</div>}
      </div>
      <div className="windows-source-note">The agent reads Security events 4624/4625, sends a heartbeat, starts from the current log position, checkpoints acknowledged batches, and retries safely. Run the isolated receiver as <code>uvicorn app.collector:app --host COLLECTOR_LAN_IP --port 8001</code>; it exposes only health and bearer-token ingestion routes. Keep the dashboard API on loopback, firewall port 8001 to the Windows collector, and use HTTPS or a trusted VPN because HTTP bearer tokens are readable on-path.</div>
    </section>
  );
}
