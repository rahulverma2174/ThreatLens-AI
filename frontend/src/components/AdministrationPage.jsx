import { useState } from "react";
import { ServerCog, ShieldCheck } from "lucide-react";

import WindowsSourcesPanel from "./WindowsSourcesPanel";

export default function AdministrationPage({ onError, onSuccess }) {
  const [notice, setNotice] = useState("");
  function success(message) {
    setNotice(message);
    onSuccess?.(message);
  }

  return (
    <div className="page-content">
      <div className="page-heading"><div><div className="eyebrow"><ServerCog size={13} />LOCAL WORKSPACE <span className="heading-divider">/</span> SOURCES</div><h1>Administration</h1><p>Review and manage registered collector sources for this local workspace.</p></div><span className="local-only">LOCAL ACCESS</span></div>
      {notice && <div className="model-notice"><ShieldCheck size={14} /><span>{notice}</span></div>}
      <WindowsSourcesPanel onError={onError} onSuccess={success} />
    </div>
  );
}
