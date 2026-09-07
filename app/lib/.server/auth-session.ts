/**
 * Authentik login session helpers (Chef auth fork, stage 3b — fork mode only).
 *
 * Flow: GET /api/auth/start → authorize redirect with a verifier+state pair
 * stashed in short-lived httpOnly cookies → Authentik → GET /api/auth/callback
 * exchanges the code (authentik.ts), stores the id_token in the httpOnly
 * `chef_session` cookie → the client reads the id_token back from
 * GET /api/auth/session and hands it to Convex via `client.setAuth` (validated
 * against the Authentik JWKS by convex/auth.config.ts).
 *
 * Session secret: CHEF_SESSION_SECRET (also used to sign the cookie).
 */

import crypto from "node:crypto";

export const SESSION_COOKIE = "chef_session";
export const VERIFIER_COOKIE = "chef_oidc_verifier";
export const STATE_COOKIE = "chef_oidc_state";

const MAX_AGE_SESSION = 60 * 60 * 24 * 7; // 7 days
const MAX_AGE_EPHEMERAL = 60 * 10; // 10 minutes (verifier/state)

export interface OidcClientEnv {
  issuer: string;
  clientId: string;
  clientSecret: string;
  enabled: boolean;
}

export function oidcEnv(): OidcClientEnv {
  const issuer = process.env.CHEF_OIDC_ISSUER_URL ?? "";
  return {
    issuer,
    clientId: process.env.CHEF_OIDC_CLIENT_ID ?? "atlas-chef",
    clientSecret: process.env.CHEF_OIDC_CLIENT_SECRET ?? "",
    enabled: Boolean(issuer && process.env.CHEF_OIDC_CLIENT_SECRET),
  };
}

export function sessionSecret(): string {
  return process.env.CHEF_SESSION_SECRET ?? "";
}

export function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}

function setCookie(
  name: string,
  value: string,
  opts: { maxAge: number; httpOnly: boolean },
): string {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    `Max-Age=${opts.maxAge}`,
    "Path=/",
    "SameSite=Lax",
  ];
  if (opts.httpOnly) parts.push("HttpOnly");
  if (process.env.NODE_ENV === "production") parts.push("Secure");
  return parts.join("; ");
}

export function sessionCookieValue(idToken: string): string {
  const secret = sessionSecret();
  // Sign so a forged/rotated cookie can't be presented as a session.
  const sig = crypto
    .createHmac("sha256", secret || "unset-secret")
    .update(idToken)
    .digest("base64url");
  return `${idToken}.${sig}`;
}

export function verifySessionCookie(value: string): string | null {
  const secret = sessionSecret();
  const dot = value.lastIndexOf(".");
  if (dot <= 0) return null;
  const idToken = value.slice(0, dot);
  const sig = value.slice(dot + 1);
  const expected = crypto
    .createHmac("sha256", secret || "unset-secret")
    .update(idToken)
    .digest("base64url");
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return idToken;
}

export function setSessionCookie(idToken: string): string {
  return setCookie(SESSION_COOKIE, sessionCookieValue(idToken), {
    maxAge: MAX_AGE_SESSION,
    httpOnly: true,
  });
}

export function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; Max-Age=0; Path=/; SameSite=Lax; HttpOnly${
    process.env.NODE_ENV === "production" ? "; Secure" : ""
  }`;
}

export function setEphemeralCookie(name: string, value: string): string {
  return setCookie(name, value, { maxAge: MAX_AGE_EPHEMERAL, httpOnly: true });
}

export function clearEphemeralCookie(name: string): string {
  return `${name}=; Max-Age=0; Path=/; SameSite=Lax; HttpOnly${
    process.env.NODE_ENV === "production" ? "; Secure" : ""
  }`;
}

/** The app origin (scheme://host) from the request — used as redirect_uri base. */
export function requestOrigin(request: Request): string {
  const url = new URL(request.url);
  return url.origin;
}
