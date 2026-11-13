import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { LockKeyhole, ShieldCheck } from "lucide-react";
import { apiRequest, setCsrfToken } from "../api";

const AuthContext = createContext({ required: false, username: "Local analyst", logout: async () => {} });
export const useAuth = () => useContext(AuthContext);

function LoginScreen({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const session = await apiRequest("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      onLogin(session);
      setPassword("");
    } catch {
      setError("Unable to sign in. Check your credentials or try again later.");
    } finally {
      setBusy(false);
    }
  }

  return <main className="auth-screen"><section className="auth-card" aria-labelledby="auth-title">
    <div className="auth-brand"><span><ShieldCheck size={21} /></span><div><strong>THREATLENS AI</strong><small>SECURITY OPERATIONS</small></div></div>
    <div className="auth-kicker"><LockKeyhole size={13} /> DEMO WORKSPACE</div>
    <h1 id="auth-title">Analyst sign in</h1><p>Use the configured demonstration account to access this workspace.</p>
    <form onSubmit={submit}>
      <label>Username<input autoComplete="username" required maxLength={128} value={username} onChange={(event) => setUsername(event.target.value)} /></label>
      <label>Password<input autoComplete="current-password" type="password" required maxLength={1024} value={password} onChange={(event) => setPassword(event.target.value)} /></label>
      {error && <div className="auth-error" role="alert">{error}</div>}
      <button type="submit" disabled={busy}>{busy ? "Verifying…" : "Sign in securely"}</button>
    </form>
    <small className="auth-footnote">Session access is temporary and protected by this server.</small>
  </section></main>;
}

export default function AuthGate({ children }) {
  const [status, setStatus] = useState(null);
  const [fatalError, setFatalError] = useState(false);

  const applySession = useCallback((session) => {
    setCsrfToken(session.csrf_token);
    setStatus({ auth_required: Boolean(session.auth_required), authenticated: Boolean(session.authenticated), username: session.username });
    setFatalError(false);
  }, []);

  useEffect(() => {
    let active = true;
    const expire = () => {
      setCsrfToken(null);
      setStatus((current) => current?.auth_required ? { ...current, authenticated: false } : current);
    };
    window.addEventListener("threatlens:auth-required", expire);
    apiRequest("/api/auth/session").then((session) => { if (active) applySession(session); }).catch(() => { if (active) setFatalError(true); });
    return () => { active = false; window.removeEventListener("threatlens:auth-required", expire); };
  }, [applySession]);

  const logout = useCallback(async () => {
    try { await apiRequest("/api/auth/logout", { method: "POST" }); } finally {
      setCsrfToken(null);
      window.dispatchEvent(new CustomEvent("threatlens:auth-required"));
    }
  }, []);

  if (fatalError) return <main className="auth-screen"><div className="auth-card" role="alert"><h1>Service unavailable</h1><p>The authentication service could not be reached.</p><button onClick={() => window.location.reload()}>Retry connection</button></div></main>;
  if (!status) return <main className="auth-screen" role="status"><div className="auth-card">Connecting to the authentication service…</div></main>;
  if (status.auth_required && !status.authenticated) return <LoginScreen onLogin={applySession} />;

  return <AuthContext.Provider value={{ required: status.auth_required, username: status.username || "Local analyst", logout }}>{children}</AuthContext.Provider>;
}
