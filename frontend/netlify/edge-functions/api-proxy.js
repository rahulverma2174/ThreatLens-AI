// Forwards /api/* requests to the ThreatLens FastAPI backend.
// Set THREATLENS_API_URL (e.g. https://threatlens-api.example.com) in the Netlify
// environment variables to point at wherever the Python backend is hosted.
export default async (req) => {
  const backend = Netlify.env.get("THREATLENS_API_URL");
  if (!backend) {
    return Response.json(
      { detail: "Backend not configured. Set THREATLENS_API_URL to the hosted ThreatLens API." },
      { status: 503 },
    );
  }

  const incoming = new URL(req.url);
  const target = new URL(incoming.pathname + incoming.search, backend.replace(/\/+$/, "") + "/");

  const headers = new Headers(req.headers);
  headers.delete("host");
  headers.set("x-forwarded-host", incoming.host);
  headers.set("x-forwarded-proto", incoming.protocol.replace(":", ""));

  const hasBody = !["GET", "HEAD"].includes(req.method);
  try {
    const upstream = await fetch(target, {
      method: req.method,
      headers,
      body: hasBody ? req.body : undefined,
      redirect: "manual",
      ...(hasBody ? { duplex: "half" } : {}),
    });
    return new Response(upstream.body, { status: upstream.status, headers: upstream.headers });
  } catch {
    return Response.json({ detail: "ThreatLens API is unreachable." }, { status: 502 });
  }
};

export const config = { path: "/api/*" };
