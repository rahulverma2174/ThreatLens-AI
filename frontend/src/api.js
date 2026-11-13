let csrfToken = null;

export function setCsrfToken(value) {
  csrfToken = value || null;
}

export async function apiRequest(path, options = {}) {
  const headers = new Headers(options.headers ?? {});
  const method = (options.method ?? "GET").toUpperCase();
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && csrfToken) headers.set("X-CSRF-Token", csrfToken);
  const response = await fetch(path, { ...options, headers, credentials: "include" });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      message = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
    } catch {
      // Keep the HTTP status message when an error response is not JSON.
    }
    if (response.status === 401 && !["/api/auth/login", "/api/auth/session"].includes(path)) {
      setCsrfToken(null);
      window.dispatchEvent(new CustomEvent("threatlens:auth-required"));
    }
    throw new Error(message);
  }
  if (response.status === 204) return null;
  if (response.headers.get("content-type")?.includes("text/csv")) return response;
  return response.json();
}

export function formatDate(value) {
  if (!value) return "—";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}
