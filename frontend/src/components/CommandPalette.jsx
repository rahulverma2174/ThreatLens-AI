import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowRight, Command, Search, X } from "lucide-react";
import Dialog from "./ui/Dialog";

const destinations = [
  { id: "overview", label: "SOC Command Center", group: "Workspace" },
  { id: "events", label: "Event Explorer", group: "Investigate" },
  { id: "detection-engineering", label: "Detection Engineering", group: "Monitor" },
  { id: "attack", label: "MITRE ATT&CK Coverage", group: "Monitor" },
  { id: "alerts", label: "Threat Detection", group: "Investigate" },
  { id: "incidents", label: "Incident Queue", group: "Respond" },
  { id: "soar", label: "SOAR Workflow Builder", group: "Respond" },
  { id: "investigation", label: "IP Intelligence", group: "Investigate" },
  { id: "relationships", label: "Relationship Graph", group: "Investigate" },
  { id: "anomaly", label: "AI Analytics Studio", group: "Analyze" },
  { id: "copilot", label: "Security Copilot", group: "Analyze" },
  { id: "reports", label: "Reports", group: "Workspace" },
  { id: "administration", label: "Administration", group: "Govern", adminOnly: true },
  { id: "settings", label: "Settings", group: "Workspace" },
];

export default function CommandPalette({ open, onClose, onNavigate, onSearch, identity }) {
  const inputRef = useRef(null);
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => {
    const term = query.trim().toLowerCase();
    return destinations.filter((item) => (!item.adminOnly || identity?.role === "admin") && (!term || `${item.label} ${item.group}`.toLowerCase().includes(term)));
  }, [identity, query]);

  useEffect(() => {
    if (!open) setQuery("");
  }, [open]);

  function handleKeyDown(event) {
    if (event.key !== "Enter") return;
    event.preventDefault();
    if (query.trim()) {
      onSearch(query.trim());
      onClose();
    } else if (filtered[0]) {
      onNavigate(filtered[0].id);
      onClose();
    }
  }

  function runSearch(search) {
    onSearch(search);
    onClose();
  }

  return (
    <Dialog open={open} onClose={onClose} className="command-overlay" dialogClassName="command-palette" label="Global command search" initialFocusRef={inputRef}>
          <div className="command-search-row"><Search size={17} /><input ref={inputRef} aria-label="Search commands and pages" placeholder="Search pages or local events…" value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={handleKeyDown} /><kbd>ESC</kbd><button className="icon-quiet" onClick={onClose} aria-label="Close command palette"><X size={15} /></button></div>
          <div className="command-content">
            <div className="command-section-label"><Command size={12} />WORKSPACE DESTINATIONS</div>
            <div className="command-results">
              {filtered.map((item) => <button key={item.id} className="command-result" onClick={() => { onNavigate(item.id); onClose(); }}>
                <span className="command-result-icon">{item.label.slice(0, 1)}</span><span><strong>{item.label}</strong><small>{item.group}</small></span><ArrowRight size={14} />
              </button>)}
              {!filtered.length && <div className="command-empty">No workspace destinations match.</div>}
            </div>
            {query.trim() && <button className="command-event-search" onClick={() => runSearch(query.trim())}><Search size={14} /><span>Search local events for <strong>{query.trim()}</strong></span><kbd>ENTER</kbd></button>}
          </div>
          <footer className="command-footer"><span><kbd>TAB</kbd> Focus actions</span><span><kbd>↵</kbd> Search / select</span><span><kbd>ESC</kbd> Close</span></footer>
    </Dialog>
  );
}
