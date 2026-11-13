import type { DiagramState, ViewState } from "../types";

export interface SharedDoc {
  doc: DiagramState;
  view: ViewState;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlToBytes(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function gzipCompress(text: string): Promise<Uint8Array | null> {
  if (typeof CompressionStream === "undefined") return null;
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("gzip"));
  const buf = await new Response(stream).arrayBuffer();
  return new Uint8Array(buf);
}

async function gzipDecompress(bytes: Uint8Array): Promise<string | null> {
  if (typeof DecompressionStream === "undefined") return null;
  const stream = new Blob([bytes.slice().buffer]).stream().pipeThrough(new DecompressionStream("gzip"));
  const buf = await new Response(stream).arrayBuffer();
  return new TextDecoder().decode(buf);
}

export async function encodeDoc(doc: DiagramState, view: ViewState): Promise<string> {
  const text = JSON.stringify({ doc, view });
  const gz = await gzipCompress(text);
  if (gz) return "g" + bytesToBase64Url(gz);
  return "p" + bytesToBase64Url(new TextEncoder().encode(text));
}

export async function decodeDoc(hash: string): Promise<SharedDoc | null> {
  try {
    const mode = hash[0];
    const payload = hash.slice(1);
    const bytes = base64UrlToBytes(payload);
    if (mode === "g") {
      const text = await gzipDecompress(bytes);
      if (!text) return null;
      return JSON.parse(text) as SharedDoc;
    }
    const text = new TextDecoder().decode(bytes);
    return JSON.parse(text) as SharedDoc;
  } catch {
    return null;
  }
}

export function clearShareHash() {
  try {
    history.replaceState(null, "", location.pathname + location.search);
  } catch {
    /* ignore */
  }
}
