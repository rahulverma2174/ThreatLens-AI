import { Activity, Beaker, BrainCircuit, Crosshair, FileBarChart2, Fingerprint, LayoutDashboard, MessageSquareText, Network, Radar, Search, Settings2, ShieldAlert, Siren, SlidersHorizontal, ScrollText, ServerCog, Workflow } from "lucide-react";
import { motion, useReducedMotion } from "framer-motion";

const links = [
  { id: "overview", label: "Overview", icon: LayoutDashboard, group: "WORKSPACE" },
  { id: "events", label: "Live monitoring", icon: Activity },
  { id: "hunting", label: "Threat Hunting", icon: Search },
  { id: "detection-lab", label: "Detection Validation Lab", icon: Beaker },
  { id: "threat-intelligence", label: "Threat Intelligence", icon: Radar },
  { id: "detection-engineering", label: "Detection engineering", icon: SlidersHorizontal },
  { id: "attack", label: "ATT&CK coverage", icon: Crosshair },
  { id: "alerts", label: "Threat detection", icon: ShieldAlert, badge: "detections" },
  { id: "anomaly", label: "AI analysis", icon: BrainCircuit },
  { id: "relationships", label: "Attack relationships", icon: Network },
  { id: "investigation", label: "IP intelligence", icon: Fingerprint, group: "RESPONSE" },
  { id: "incidents", label: "Incident management", icon: Siren, badge: "incidents" },
  { id: "soar", label: "SOAR workflows", icon: Workflow },
  { id: "reports", label: "Reports", icon: FileBarChart2 },
  { id: "audit", label: "Audit history", icon: ScrollText },
  { id: "administration", label: "Administration", icon: ServerCog, group: "GOVERN", adminOnly: true },
  { id: "copilot", label: "Security Copilot", icon: MessageSquareText, group: "ASSIST" },
];

function initials(value = "A") {
  return value.split(/[ ._-]+/).filter(Boolean).slice(0, 2).map((part) => part[0]?.toUpperCase()).join("") || "A";
}

export default function Sidebar({ page, onNavigate, alertCount, incidentCount, apiStatus, collapsed = false, identity }) {
  let group = "";
  const reduceMotion = useReducedMotion();
  const visibleLinks = links.filter((item) => !item.adminOnly || identity?.role === "admin");
  return (
    <aside id="primary-navigation-drawer" className={`sidebar ${collapsed ? "is-collapsed" : ""}`} aria-label="ThreatLens primary navigation">
      <button className="sidebar-brand" onClick={() => onNavigate("overview")} aria-label="ThreatLens AI overview">
        <span className="brand-mark"><ShieldAlert size={18} /></span>
        <span className="brand-copy"><strong>ThreatLens <em>AI</em></strong><small>SECURITY OPERATIONS</small></span>
        <span className="brand-build">TL</span>
      </button>
      <div className="tenant-switch" title="Local SQLite workspace. Data provenance is not inferred."><span className="tenant-glyph">L</span><span className="tenant-copy"><strong>Local workspace</strong><small>LOCAL SQLITE INSTANCE</small></span></div>
      <nav className="nav-list" aria-label="Main navigation" tabIndex={0}>
        {visibleLinks.map(({ id, label, icon: Icon, group: nextGroup, badge }) => {
          const showGroup = nextGroup && nextGroup !== group;
          group = nextGroup || group;
          const count = badge === "detections" ? alertCount : badge === "incidents" ? incidentCount : 0;
          return (
            <div key={id}>
              {showGroup && <div className="nav-caption">{nextGroup}</div>}
              <button className={`nav-item ${page === id ? "active" : ""}`} onClick={() => onNavigate(id)} aria-current={page === id ? "page" : undefined} aria-label={label} title={collapsed ? label : undefined}>
                {page === id && <motion.span className="nav-active-indicator" layoutId="threatlens-active-navigation" aria-hidden="true" transition={reduceMotion ? { duration: 0 } : { type: "spring", stiffness: 620, damping: 44 }} />}
                <Icon size={16} strokeWidth={1.8} /><span>{label}</span>
                {count > 0 && <b className={`nav-count ${badge}`}>{count}</b>}
              </button>
            </div>
          );
        })}
      </nav>
      <div className="sidebar-spacer" />
      <button className={`nav-item settings-link ${page === "settings" ? "active" : ""}`} onClick={() => onNavigate("settings")} aria-current={page === "settings" ? "page" : undefined}><Settings2 size={16} /><span>Settings</span></button>
      <div className="sidebar-status" title={`API ${apiStatus}`}><span className={`status-pulse ${apiStatus === "Connected" ? "" : "paused"}`} /><span><strong>{apiStatus === "Connected" ? "API connected" : `API ${apiStatus.toLowerCase()}`}</strong><small>{apiStatus === "Connected" ? "LOCAL ENGINE · NOMINAL" : "CHECK API CONNECTION"}</small></span></div>
      <div className="sidebar-profile"><div className="profile-avatar">{initials(identity?.username)}</div><span><strong>{identity?.username || "Analyst"}</strong><small>{identity?.role?.toUpperCase() || "ANALYST"}</small></span></div>
      <div className="sidebar-version">THREATLENS AI <span>v0.3.0</span><i>LOCAL INSTANCE</i></div>
    </aside>
  );
}
