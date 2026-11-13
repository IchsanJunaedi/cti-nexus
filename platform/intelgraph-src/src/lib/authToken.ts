const TOKEN_SS_KEY = "netdraw:token";

function captureFromHash(): string | null {
  const m = location.hash.match(/(?:^|[#&])token=([^&]+)/);
  if (!m) return null;
  const token = decodeURIComponent(m[1]);
  try {
    const rest = location.hash.replace(/(?:^|[#&])token=[^&]+/, "").replace(/^#&/, "#");
    const cleaned = rest === "#" || rest === "" ? location.pathname + location.search : location.pathname + location.search + rest;
    history.replaceState(null, "", cleaned);
  } catch {
    /* ignore */
  }
  try {
    sessionStorage.setItem(TOKEN_SS_KEY, token);
  } catch {
    /* storage unavailable */
  }
  return token;
}

let cachedToken: string | null = captureFromHash();

export function getToken(): string | null {
  if (cachedToken) return cachedToken;
  try {
    cachedToken = sessionStorage.getItem(TOKEN_SS_KEY);
  } catch {
    cachedToken = null;
  }
  return cachedToken;
}

export interface UserInfo {
  username: string;
  role: string;
}

/** UI hint only — no signature verification. The backend is the real authorization boundary;
 * this just lets the UI grey out actions it already knows the server will reject. */
export function getUserInfo(): UserInfo | null {
  const token = getToken();
  if (!token) return null;
  try {
    const payloadB64 = token.split(".")[1];
    const json = atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/"));
    const payload = JSON.parse(decodeURIComponent(escape(json)));
    if (!payload.sub) return null;
    return { username: payload.sub as string, role: (payload.role as string) ?? "analyst" };
  } catch {
    return null;
  }
}
