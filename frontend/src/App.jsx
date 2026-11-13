import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { Bell, ChevronDown, CircleHelp, Menu, PanelLeftClose, PanelLeftOpen, Radio, RefreshCw, Search, ShieldCheck, X } from "lucide-react";

import { apiRequest } from "./api";
import CommandPalette from "./components/CommandPalette";
import Sidebar from "./components/Sidebar";
import Button from "./components/ui/Button";
import ErrorState from "./components/ui/ErrorState";
import LoadingState from "./components/ui/LoadingState";
import AuthGate, { useAuth } from "./components/AuthGate";

const AlertsPage = lazy(() => import("./components/AlertsPage"));
const AttackCoveragePage = lazy(() => import("./components/AttackCoveragePage"));
const AdministrationPage = lazy(() => import("./components/AdministrationPage"));
const AuditPage = lazy(() => import("./components/AuditPage"));
const AnomalyPage = lazy(() => import("./components/AnomalyPage"));
const CopilotPage = lazy(() => import("./components/CopilotPage"));
const DetectionEngineeringPage = lazy(() => import("./components/DetectionEngineeringPage"));
const EventsPage = lazy(() => import("./components/EventsPage"));
const IncidentPage = lazy(() => import("./components/IncidentPage"));
const InvestigationPage = lazy(() => import("./components/InvestigationPage"));
const Overview = lazy(() => import("./components/Overview"));
const RelationshipsPage = lazy(() => import("./components/RelationshipsPage"));
const ReportsPage = lazy(() => import("./components/ReportsPage"));
const SettingsPage = lazy(() => import("./components/SettingsPage"));
const SoarPage = lazy(() => import("./components/SoarPage"));
const ThreatHuntingPage = lazy(() => import("./components/ThreatHuntingPage"));
const DetectionLabPage = lazy(() => import("./components/DetectionLabPage"));
const ThreatIntelligencePage = lazy(() => import("./components/ThreatIntelligencePage"));

const pageTitles = {
  overview: "Overview",
  events: "Live monitoring",
  "detection-engineering": "Detection Engineering",
  hunting: "Threat Hunting",
  "detection-lab": "Detection Validation Lab",
  "threat-intelligence": "Threat Intelligence",
  alerts: "Threat detection",
  attack: "ATT&CK coverage",
  soar: "SOAR workflows",
  audit: "Audit history",
  anomaly: "AI analysis",
  investigation: "IP intelligence",
  incidents: "Incident management",
  reports: "Reports",
  relationships: "Attack relationships",
  copilot: "Security Copilot",
  settings: "Settings",
  administration: "Administration",
};

function currentTime() {
  return new Intl.DateTimeFormat(undefined, {
    weekday: "short", month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  }).format(new Date());
}

function formatDateSafe(value) {
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" }).format(new Date(value));
}

function HeaderClock() {
  const [clock, setClock] = useState(currentTime);
  useEffect(() => {
    const timer = window.setInterval(() => setClock(currentTime()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  return <span className="header-clock">{clock}</span>;
}

function DashboardApp() {
  const auth = useAuth();
  const [page, setPage] = useState("overview");
  const [mobileMenu, setMobileMenu] = useState(false);
  const mobileMenuButtonRef = useRef(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => localStorage.getItem("threatlens.sidebar-collapsed") === "true");
  const [commandOpen, setCommandOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(() => localStorage.getItem("threatlens.auto-refresh") !== "false");
  const refreshLock = useRef(false);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [stats, setStats] = useState(null);
  const [sources, setSources] = useState([]);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [events, setEvents] = useState([]);
  const [dashboardEvents, setDashboardEvents] = useState([]);
  const [eventCount, setEventCount] = useState(0);
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [apiStatus, setApiStatus] = useState("Connecting");
  const [monitoringEnabled, setMonitoringEnabled] = useState(true);
  const [globalSearch, setGlobalSearch] = useState("");
  const [globalSearchResults, setGlobalSearchResults] = useState([]);
  const [globalSearchOpen, setGlobalSearchOpen] = useState(false);
  const [globalSearching, setGlobalSearching] = useState(false);
  const [eventQuery, setEventQuery] = useState("");
  const [alertQuery, setAlertQuery] = useState("");
  const [incidentQuery, setIncidentQuery] = useState("");
  const [initialIncidentId, setInitialIncidentId] = useState(null);
  const [investigationIP, setInvestigationIP] = useState("");
  const [notificationOpen, setNotificationOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const profileWrapRef = useRef(null);
  const profileButtonRef = useRef(null);
  const reduceMotion = useReducedMotion();

  const notifyError = useCallback((message) => {
    setToast(message);
    window.setTimeout(() => setToast(""), 5000);
  }, []);
  const notifySuccess = useCallback((message) => {
    setToast(message);
    window.setTimeout(() => setToast(""), 3500);
  }, []);

  const refresh = useCallback(async (background = false) => {
    if (refreshLock.current) return;
    refreshLock.current = true;
    if (background) setRefreshing(true);
    else setLoading(true);
    setError("");
    try {
      const [health, summary, latestEvents, latestAlerts, latestIncidents, detectionSettings, count, localSources] = await Promise.all([
        apiRequest("/api/health"),
        apiRequest("/api/dashboard/stats"),
        apiRequest("/api/events?limit=100"),
        apiRequest("/api/alerts"),
        apiRequest("/api/incidents"),
        apiRequest("/api/settings/detection"),
        apiRequest("/api/events/count"),
        apiRequest("/api/ingestion/sources").catch(() => []),
      ]);
      setApiStatus(health.status === "ok" ? "Connected" : "Unavailable");
      setMonitoringEnabled(detectionSettings.monitoring_enabled);
      setStats(summary);
      setEvents(latestEvents);
      setDashboardEvents(latestEvents);
      setEventCount(count.total);
      setAlerts(latestAlerts);
      setIncidents(latestIncidents);
      setSources(localSources);
      setLastRefresh(new Date().toISOString());
    } catch (requestError) {
      setApiStatus("Offline");
      setError(requestError.message);
    } finally {
      setLoading(false);
      setRefreshing(false);
      refreshLock.current = false;
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (!profileOpen) return undefined;
    profileWrapRef.current?.querySelector(".profile-popover-actions button")?.focus();
    const dismissOutside = (event) => {
      if (!profileWrapRef.current?.contains(event.target)) setProfileOpen(false);
    };
    const dismissEscape = (event) => {
      if (event.key !== "Escape") return;
      setProfileOpen(false);
      profileButtonRef.current?.focus();
    };
    document.addEventListener("pointerdown", dismissOutside);
    document.addEventListener("keydown", dismissEscape);
    return () => {
      document.removeEventListener("pointerdown", dismissOutside);
      document.removeEventListener("keydown", dismissEscape);
    };
  }, [profileOpen]);

  useEffect(() => {
    localStorage.setItem("threatlens.sidebar-collapsed", String(sidebarCollapsed));
  }, [sidebarCollapsed]);

  useEffect(() => {
    localStorage.setItem("threatlens.auto-refresh", String(autoRefresh));
    if (!autoRefresh) return undefined;
    const poll = () => { if (document.visibilityState === "visible") refresh(true); };
    const timer = window.setInterval(poll, 20_000);
    document.addEventListener("visibilitychange", poll);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", poll);
    };
  }, [autoRefresh, refresh]);

  useEffect(() => {
    function handleShortcuts(event) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setCommandOpen((open) => !open);
      } else if (event.key === "Escape") {
        setCommandOpen(false);
      }
    }
    window.addEventListener("keydown", handleShortcuts);
    return () => window.removeEventListener("keydown", handleShortcuts);
  }, []);

  useEffect(() => {
    if (!mobileMenu) return undefined;
    const previousFocus = document.activeElement;
    const firstNavigationItem = document.querySelector(".sidebar-holder.mobile-open .nav-item");
    firstNavigationItem?.focus();
    const keepFocusInDrawer = (event) => {
      if (event.key === "Escape") {
        setMobileMenu(false);
        mobileMenuButtonRef.current?.focus();
        return;
      }
      if (event.key !== "Tab") return;
      const drawer = document.querySelector(".sidebar-holder.mobile-open");
      const focusable = drawer?.querySelectorAll('button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), [tabindex]:not([tabindex="-1"])');
      if (!focusable?.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", keepFocusInDrawer);
    return () => {
      document.removeEventListener("keydown", keepFocusInDrawer);
      if (previousFocus?.isConnected && previousFocus !== document.body) previousFocus.focus?.();
    };
  }, [mobileMenu]);

  const navigate = useCallback((target) => {
    setPage(target);
    setMobileMenu(false);
    setNotificationOpen(false);
    setHelpOpen(false);
    setProfileOpen(false);
  }, []);

  const searchEvents = useCallback(async ({ search = "", status = "", eventType = "", limit = 25, offset = 0 }) => {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    const countParams = new URLSearchParams();
    if (search.trim()) { params.set("search", search.trim()); countParams.set("search", search.trim()); }
    if (status) { params.set("status", status); countParams.set("status", status); }
    if (eventType) { params.set("event_type", eventType); countParams.set("event_type", eventType); }
    try {
      const [records, count] = await Promise.all([
        apiRequest(`/api/events?${params}`),
        apiRequest(`/api/events/count${countParams.size ? `?${countParams}` : ""}`),
      ]);
      setEvents(records);
      setEventCount(count.total);
    } catch (requestError) {
      notifyError(requestError.message);
    }
  }, [notifyError]);

  useEffect(() => {
    const query = globalSearch.trim();
    if (query.length < 2) {
      setGlobalSearchResults([]);
      setGlobalSearching(false);
      return undefined;
    }
    let active = true;
    const timer = window.setTimeout(async () => {
      setGlobalSearching(true);
      try {
        const result = await apiRequest(`/api/search?q=${encodeURIComponent(query)}&limit=5`);
        if (active) setGlobalSearchResults(result.results);
      } catch (searchError) {
        if (active) setGlobalSearchResults([]);
      } finally {
        if (active) setGlobalSearching(false);
      }
    }, 220);
    return () => { active = false; window.clearTimeout(timer); };
  }, [globalSearch]);

  const searchNaturalEvents = useCallback(async ({ query, limit = 25, offset = 0 }) => {
    const result = await apiRequest("/api/events/natural-search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query, limit, offset }),
    });
    setEvents(result.events);
    setEventCount(result.total);
    return result;
  }, []);

  async function submitGlobalSearch(event) {
    event.preventDefault();
    const query = globalSearch.trim();
    if (query.length < 2) return;
    setGlobalSearchOpen(true);
    if (globalSearchResults.length === 1) selectGlobalResult(globalSearchResults[0]);
  }

  function selectGlobalResult(result) {
    setGlobalSearchOpen(false);
    setGlobalSearch("");
    if (result.kind === "incident") {
      setIncidentQuery(result.title);
      setInitialIncidentId(result.id);
      navigate("incidents");
    } else if (result.kind === "alert") {
      setAlertQuery(result.title);
      navigate("alerts");
    } else {
      const query = result.source_ip || result.username || globalSearch.trim();
      setEventQuery(query);
      navigate("events");
      searchEvents({ search: query, limit: 25, offset: 0 });
    }
  }

  async function uploadEvents(file) {
    const data = new FormData();
    data.append("file", file);
    try {
      const result = await apiRequest("/api/events/upload", { method: "POST", body: data });
      notifySuccess(`Import run #${result.run_id} completed: ${result.accepted_records} accepted, ${result.rejected_records} rejected.`);
      await refresh(true);
    } catch (requestError) {
      notifyError(requestError.message);
    }
  }

  const updateIncident = useCallback(async (id, changes) => {
    try {
      await apiRequest(`/api/incidents/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(changes),
      });
      notifySuccess(changes.status ? `Incident marked ${changes.status}.` : "Analyst notes saved.");
      await refresh(true);
    } catch (requestError) {
      notifyError(requestError.message);
      throw requestError;
    }
  }, [notifyError, notifySuccess, refresh]);

  const bulkUpdateAlertStatus = useCallback(async (alertIds, status) => {
    const result = await apiRequest("/api/alerts/bulk", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert_ids: alertIds, status }),
    });
    notifySuccess(`${result.updated_count} alert${result.updated_count === 1 ? "" : "s"} marked ${status}.`);
    await refresh(true);
    return result;
  }, [notifySuccess, refresh]);

  const investigateIP = useCallback((ip) => {
    setInvestigationIP(ip);
    navigate("investigation");
  }, [navigate]);

  const openIncident = useCallback((incidentId) => {
    setInitialIncidentId(incidentId);
    navigate("incidents");
  }, [navigate]);

  const activeAlerts = useMemo(() => alerts.filter((alert) => alert.status !== "resolved"), [alerts]);
  const activeIncidents = useMemo(() => incidents.filter((incident) => incident.status !== "resolved"), [incidents]);

  let content;
  switch (page) {
    case "events":
      content = <EventsPage key={eventQuery} initialQuery={eventQuery} events={events} totalCount={eventCount} alerts={alerts} onSearch={searchEvents} onNaturalSearch={searchNaturalEvents} onUpload={uploadEvents} onInvestigate={investigateIP} onError={notifyError} />;
      break;
    case "hunting": content = <ThreatHuntingPage onError={notifyError} onInvestigate={investigateIP} onOpenIncident={openIncident} onNavigate={navigate} />; break;
    case "detection-lab": content = <DetectionLabPage onError={notifyError} onSuccess={notifySuccess} />; break;
    case "threat-intelligence": content = <ThreatIntelligencePage demoMode={auth.required} onError={notifyError} onSuccess={notifySuccess} onInvestigate={investigateIP} onNavigate={navigate} />; break;
    case "detection-engineering": content = <DetectionEngineeringPage onError={notifyError} onSuccess={notifySuccess} />; break;
    case "alerts": content = <AlertsPage key={alertQuery} initialQuery={alertQuery} alerts={alerts} onNavigate={navigate} onBulkStatusUpdate={bulkUpdateAlertStatus} onError={notifyError} />; break;
    case "attack": content = <AttackCoveragePage onError={notifyError} />; break;
    case "soar": content = <SoarPage onError={notifyError} onSuccess={notifySuccess} />; break;
    case "audit": content = <AuditPage onError={notifyError} />; break;
    case "incidents": content = <IncidentPage key={`${initialIncidentId ?? ""}:${incidentQuery}`} initialQuery={incidentQuery} initialIncidentId={initialIncidentId} incidents={incidents} alerts={alerts} onUpdate={updateIncident} onError={notifyError} onNavigate={navigate} onInvestigate={investigateIP} />; break;
    case "investigation": content = <InvestigationPage key={investigationIP} initialIP={investigationIP} alerts={alerts} onError={notifyError} onSuccess={notifySuccess} />; break;
    case "anomaly": content = <AnomalyPage onError={notifyError} />; break;
    case "relationships": content = <RelationshipsPage onError={notifyError} onInvestigate={investigateIP} />; break;
    case "copilot": content = <CopilotPage onError={notifyError} />; break;
    case "reports": content = <ReportsPage onError={notifyError} />; break;
    case "settings": content = <SettingsPage canAdmin={!auth.required} onError={notifyError} onSuccess={async (message) => { notifySuccess(message); await refresh(true); }} />; break;
    case "administration": content = <AdministrationPage onError={notifyError} onSuccess={notifySuccess} />; break;
    default: content = <Overview stats={stats} events={dashboardEvents} alerts={alerts} incidents={incidents} sources={sources} eventCount={stats?.total_events ?? eventCount} apiStatus={apiStatus} monitoringEnabled={monitoringEnabled} refreshing={refreshing} lastRefresh={lastRefresh} onRefresh={() => refresh(true)} onNavigate={navigate} onInvestigate={investigateIP} onError={notifyError} loading={loading} />;
  }

  return (
    <div className={`app-shell ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}>
      {mobileMenu && <button className="mobile-scrim" onClick={() => { setMobileMenu(false); mobileMenuButtonRef.current?.focus(); }} aria-label="Close navigation" />}
      <div className={`sidebar-holder ${mobileMenu ? "mobile-open" : ""}`}><Sidebar page={page} onNavigate={navigate} alertCount={activeAlerts.length} incidentCount={activeIncidents.length} apiStatus={apiStatus} collapsed={sidebarCollapsed} identity={{ role: auth.required ? "analyst" : "admin", username: auth.username }} onToggleCollapse={() => setSidebarCollapsed((value) => !value)} /></div>
      <div className="main-shell">
        <header className="top-header">
          <div className="header-left"><button ref={mobileMenuButtonRef} className="mobile-menu-button" onClick={() => setMobileMenu((open) => !open)} aria-label={mobileMenu ? "Close menu" : "Open menu"} aria-expanded={mobileMenu} aria-controls="primary-navigation-drawer">{mobileMenu ? <X size={17} /> : <Menu size={17} />}</button><button className="sidebar-toggle" onClick={() => setSidebarCollapsed((value) => !value)} aria-label={sidebarCollapsed ? "Expand navigation" : "Collapse navigation"} title={sidebarCollapsed ? "Expand navigation" : "Collapse navigation"} aria-expanded={!sidebarCollapsed}>{sidebarCollapsed ? <PanelLeftOpen size={15} /> : <PanelLeftClose size={15} />}</button><nav className="breadcrumb" aria-label="Breadcrumb"><button onClick={() => navigate("overview")}>ThreatLens AI</button><i aria-hidden="true">/</i><strong aria-current="page">{pageTitles[page]}</strong></nav></div>
          <div className="global-search-wrap"><form className="global-search" onSubmit={submitGlobalSearch}><Search size={14} /><input value={globalSearch} onFocus={() => setGlobalSearchOpen(true)} onChange={(event) => { setGlobalSearch(event.target.value); setGlobalSearchOpen(true); }} onKeyDown={(event) => { if (event.key === "Escape") setGlobalSearchOpen(false); }} placeholder="Search events, IPs, users, incidents…" aria-label="Search events, IPs, users, and incidents" /><kbd>CTRL K</kbd></form>{globalSearchOpen && globalSearch.trim().length >= 2 && <div className="global-search-results" role="listbox" aria-label="Search results">{globalSearching ? <div className="global-search-empty">Searching local records…</div> : globalSearchResults.length ? globalSearchResults.map((result) => <button key={`${result.kind}-${result.id}`} onClick={() => selectGlobalResult(result)} role="option"><span className={`global-result-kind ${result.kind}`}>{result.kind}</span><span><strong>{result.title}</strong><small>{result.subtitle}</small></span><kbd>↵</kbd></button>) : <div className="global-search-empty">No matching local records.</div>}</div>}</div>
          <div className="header-right">
            <span className="environment-tag" title={auth.required ? "Authenticated temporary demo session." : "Local SQLite workspace. Records may be seeded synthetic data or authorized imports; provenance is not inferred."}>{auth.required ? "DEMO · AUTHENTICATED" : "LOCAL · SQLITE"}</span><span className={`source-header-status ${sources.some((source) => source.enabled) ? "configured" : "empty"}`} title={sources.length ? `${sources.filter((source) => source.enabled).length} enabled of ${sources.length} configured sources` : "No collector source configured"}><i />{sources.length ? `SOURCES ${sources.filter((source) => source.enabled).length}/${sources.length}` : "NO SOURCES"}</span><button className={`auto-refresh-toggle ${autoRefresh ? "active" : ""}`} onClick={() => setAutoRefresh((value) => !value)} aria-pressed={autoRefresh} title={autoRefresh ? "Pause automatic data refresh" : "Resume automatic data refresh"}><Radio size={13} />{autoRefresh ? "LIVE · 20s" : "LIVE PAUSED"}</button><div className={`monitoring-pill ${apiStatus === "Connected" && monitoringEnabled ? "healthy" : "paused"}`} aria-label={`Detection rules ${monitoringEnabled ? "enabled" : "paused"}`}><i />{monitoringEnabled ? "Rules enabled" : "Rules paused"}</div><span className="header-sync-state" title={lastRefresh ? `Last successful refresh ${new Date(lastRefresh).toLocaleString()}` : "Waiting for first successful refresh"}>{lastRefresh ? `SYNC ${new Date(lastRefresh).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}` : "SYNC —"}</span><HeaderClock />
            <div className="help-wrap"><button className="header-help" onClick={() => { setHelpOpen((open) => !open); setNotificationOpen(false); setProfileOpen(false); }} aria-label="Open contextual help" aria-expanded={helpOpen}><CircleHelp size={15} /></button><AnimatePresence>{helpOpen && <motion.div className="help-popover" initial={{ opacity: 0, y: reduceMotion ? 0 : 5 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: reduceMotion ? 0 : 3 }} transition={{ duration: reduceMotion ? .06 : .12, ease: "easeOut" }}><div><strong>Workspace help</strong><button className="icon-quiet" onClick={() => setHelpOpen(false)} aria-label="Close contextual help"><X size={13} /></button></div><p>{pageTitles[page]} uses local records exposed by the FastAPI service. Model and rule findings are review signals, not confirmed attacks.</p><span><kbd>CTRL</kbd><kbd>K</kbd> Open global page and event search</span><a href="/docs" target="_blank" rel="noreferrer">Open local API documentation <span>↗</span></a></motion.div>}</AnimatePresence></div>
            <div className="notification-wrap"><button className="header-notification" onClick={() => { setNotificationOpen((open) => !open); setHelpOpen(false); setProfileOpen(false); }} aria-label="Open notification center" aria-expanded={notificationOpen}><Bell size={16} />{activeAlerts.length > 0 && <motion.span key={activeAlerts.length} initial={reduceMotion ? false : { scale: .72 }} animate={{ scale: 1 }} transition={{ duration: .16 }}>{activeAlerts.length}</motion.span>}</button>
              <AnimatePresence>{notificationOpen && <motion.div className="notification-popover" initial={{ opacity: 0, y: reduceMotion ? 0 : 5 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: reduceMotion ? 0 : 3 }} transition={{ duration: reduceMotion ? .06 : .12, ease: "easeOut" }}><div className="notification-head"><strong>Notification center</strong><span>{activeAlerts.length} active</span></div>{activeAlerts.slice(0, 5).map((alert) => <button key={alert.id} className="notification-item" onClick={() => navigate("incidents")}><span className={`severity-marker ${alert.severity}`} /><span><strong>{alert.title}</strong><small>{alert.source_ip} · {formatDateSafe(alert.created_at)}</small></span></button>)}{!activeAlerts.length && <div className="notification-empty">No active detection notifications.</div>}<button className="notification-footer" onClick={() => navigate("incidents")}>Open incident management <span>→</span></button></motion.div>}</AnimatePresence>
            </div>
            <div className="header-profile-wrap" ref={profileWrapRef}><button ref={profileButtonRef} className="header-profile" onClick={() => { setProfileOpen((open) => !open); setHelpOpen(false); setNotificationOpen(false); }} aria-label="Open analyst profile" aria-haspopup="dialog" aria-expanded={profileOpen} title="Workspace profile"><span className="header-avatar">TL</span><span className="header-workspace"><strong>{auth.required ? auth.username : "Local workspace"}</strong><small>{auth.required ? "DEMO ANALYST" : "LOCAL ACCESS"}</small></span><ChevronDown size={13} className="header-caret" /></button><AnimatePresence>{profileOpen && <motion.div className="profile-popover" role="dialog" aria-label="Analyst profile actions" initial={{ opacity: 0, y: reduceMotion ? 0 : 5 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: reduceMotion ? 0 : 3 }} transition={{ duration: reduceMotion ? .06 : .12, ease: "easeOut" }}><div className="profile-popover-identity"><span className="header-avatar">{auth.required ? auth.username.slice(0, 2).toUpperCase() : "LA"}</span><span><strong>{auth.required ? auth.username : "Local analyst"}</strong><small>{auth.required ? "DEMO ANALYST" : "ADMINISTRATOR · LOCAL INSTANCE"}</small></span></div>{auth.required ? <div className="profile-popover-actions"><button onClick={() => auth.logout().catch(() => notifyError("Sign-out request failed. Please retry."))}>Sign out</button></div> : <><div className="profile-popover-actions"><button onClick={() => navigate("settings")}>Workspace settings<ChevronDown size={13} /></button><button onClick={() => navigate("administration")}>Administration<ChevronDown size={13} /></button></div><small className="profile-popover-note">This workspace uses local access.</small></>}</motion.div>}</AnimatePresence></div>
          </div>
        </header>
        {error && <ErrorState variant="banner" message={error} action={<Button variant="secondary" size="small" icon={<RefreshCw size={13} />} onClick={() => refresh()}>Retry connection</Button>} />}
        <div className="connection-edge"><span className={apiStatus === "Connected" ? "edge-online" : "edge-offline"} /></div>
        <motion.main key={page} initial={reduceMotion ? { opacity: 0 } : { opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: reduceMotion ? .06 : .14, ease: "easeOut" }}><Suspense fallback={<LoadingState variant="workspace" label="Loading workspace view…" />}>{content}</Suspense></motion.main>
      </div>
      <CommandPalette open={commandOpen} onClose={() => setCommandOpen(false)} onNavigate={navigate} identity={{ role: auth.required ? "analyst" : "admin" }} onSearch={(query) => { setGlobalSearch(query); setEventQuery(query); navigate("events"); searchEvents({ search: query, limit: 25, offset: 0 }); }} />
      <AnimatePresence>{toast && <motion.div className="toast" role="status" initial={{ opacity: 0, y: reduceMotion ? 0 : 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: reduceMotion ? 0 : 4 }} transition={{ duration: reduceMotion ? .06 : .14, ease: "easeOut" }}><span className="toast-mark"><ShieldCheck size={14} /></span>{toast}<button onClick={() => setToast("")} aria-label="Dismiss notification"><X size={14} /></button></motion.div>}</AnimatePresence>
    </div>
  );
}

export default function App() {
  return <AuthGate><DashboardApp /></AuthGate>;
}
