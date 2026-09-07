/**
 * Authentik OIDC client — Chef auth fork (stage 3b).
 *
 * Server-side Authorization Code + PKCE grant against Cerulean's Authentik
 * so Chef can log users in without Convex's hosted WorkOS plane. The fork
 * swap (docs/chef-auth-fork.md): Chef's convex `auth.config.ts` customJwt
 * provider points at Authentik's issuer/JWKS, and this module performs the
 * browser <-> server code grant that produces the id_token the client hands
 * to Convex Auth (`useConvexAuth().setAuthToken`).
 *
 * No third-party deps: global `fetch` + `node:crypto` (WebCrypto-free RSA
 * verify via `crypto.verify` against provider JWKS keys).
 *
 * Env (CHEF_OIDC_* — see .env.example):
 *   CHEF_OIDC_ISSUER_URL     e.g. https://auth.cerulean.innotel.us/application/o/atlas-chef/
 *   CHEF_OIDC_CLIENT_ID      e.g. atlas-chef
 *   CHEF_OIDC_CLIENT_SECRET  (confidential client; the code grant happens
 *                             server-side, so the secret never reaches the
 *                             browser)
 */

import crypto from "node:crypto";

export interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
  end_session_endpoint?: string;
}

export interface IdTokenClaims {
  sub: string;
  iss: string;
  aud: string | string[];
  exp: number;
  iat?: number;
  nonce?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  groups?: string[];
}

export interface AuthentikProfile {
  sub: string;
  email: string | null;
  name: string | null;
  groups: string[];
  isAdmin: boolean;
  raw: IdTokenClaims;
}

export const env = {
  get issuer(): string {
    return process.env.CHEF_OIDC_ISSUER_URL ?? "";
  },
  get clientId(): string {
    return process.env.CHEF_OIDC_CLIENT_ID ?? "atlas-chef";
  },
  get clientSecret(): string {
    return process.env.CHEF_OIDC_CLIENT_SECRET ?? "";
  },
  get adminGroup(): string {
    return process.env.IDP_ADMIN_GROUP ?? "atlas-admins";
  },
};

export class AuthentikOidcError extends Error {
  constructor(
    public readonly code: "config" | "discovery" | "token" | "invalid_token",
    message: string,
    public readonly detail?: unknown,
  ) {
    super(message);
  }
}

// ─── tiny helpers ──────────────────────────────────────────────────────────

export function base64urlEncode(data: Buffer | string): string {
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return buf.toString("base64url");
}

export function base64urlDecode(value: string): Buffer {
  return Buffer.from(value, "base64url");
}

export function randomState(): string {
  return crypto.randomBytes(24).toString("base64url");
}

/** RFC 7636 PKCE: code_verifier (43-128 chars) + S256 challenge. */
export function pkce(): { verifier: string; challenge: string } {
  const verifier = crypto.randomBytes(48).toString("base64url"); // 64 chars
  const challenge = base64urlEncode(crypto.createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  let resp: Response;
  try {
    resp = await fetch(url, init);
  } catch (e) {
    throw new AuthentikOidcError("discovery", `request to ${url} failed`, e);
  }
  if (!resp.ok) {
    throw new AuthentikOidcError("discovery", `${url} -> HTTP ${resp.status}`, await resp.text());
  }
  return (await resp.json()) as T;
}

const discoveryCache = new Map<string, OidcDiscovery>();

export async function discover(issuer: string): Promise<OidcDiscovery> {
  const cached = discoveryCache.get(issuer);
  if (cached) return cached;
  // No leading slash: a root-relative path would drop the per-provider
  // issuer path (e.g. /application/o/atlas-chef/) and 404.
  const url = new URL(".well-known/openid-configuration", ensureTrailingSlash(issuer)).toString();
  const discovery = await fetchJson<OidcDiscovery>(url);
  if (!discovery.authorization_endpoint || !discovery.token_endpoint || !discovery.jwks_uri) {
    throw new AuthentikOidcError(
      "discovery",
      `OIDC discovery at ${issuer} is missing required endpoints`,
      discovery,
    );
  }
  discoveryCache.set(issuer, discovery);
  return discovery;
}

function ensureTrailingSlash(url: string): string {
  return url.endsWith("/") ? url : `${url}/`;
}

export async function authorizationUrl(opts: {
  issuer: string;
  clientId: string;
  redirectUri: string;
  scope?: string;
  state?: string;
  verifier?: string;
}): Promise<{ url: string; verifier: string; state: string }> {
  const verifier = opts.verifier ?? pkce().verifier;
  const state = opts.state ?? randomState();
  const challenge = base64urlEncode(crypto.createHash("sha256").update(verifier).digest());
  // Use the authorization endpoint from OIDC discovery: Authentik serves
  // authorize/token at /application/o/{authorize,token}/ (no app slug) even
  // though issuer/jwks are per-application, so deriving `${issuer}authorize/`
  // produces a 404. exchangeCode() already relies on discovery.
  const discovery = await discover(opts.issuer);
  const endpoint = discovery.authorization_endpoint;
  const params = new URLSearchParams({
    response_type: "code",
    client_id: opts.clientId,
    redirect_uri: opts.redirectUri,
    scope: opts.scope ?? "openid profile email groups",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  return { url: `${endpoint}?${params.toString()}`, verifier, state };
}

// ─── token exchange ────────────────────────────────────────────────────────

export async function exchangeCode(opts: {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  code: string;
  verifier: string;
}): Promise<{ id_token: string; access_token?: string }> {
  const discovery = await discover(opts.issuer);
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: opts.code,
    redirect_uri: opts.redirectUri,
    client_id: opts.clientId,
    client_secret: opts.clientSecret,
    code_verifier: opts.verifier,
  });
  let resp: Response;
  try {
    resp = await fetch(discovery.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
  } catch (e) {
    throw new AuthentikOidcError("token", "token endpoint request failed", e);
  }
  const json = (await resp.json().catch(() => ({}))) as Record<string, unknown>;
  if (!resp.ok) {
    throw new AuthentikOidcError(
      "token",
      `token endpoint -> HTTP ${resp.status}`,
      json,
    );
  }
  if (typeof json.id_token !== "string") {
    throw new AuthentikOidcError("token", "token response has no id_token", json);
  }
  return { id_token: json.id_token, access_token: json.access_token as string | undefined };
}

// ─── id_token verification (RS256 against provider JWKS, no deps) ─────────

export function parseJwtClaims(token: string): IdTokenClaims {
  const parts = token.split(".");
  if (parts.length !== 3) throw new AuthentikOidcError("invalid_token", "id_token is not a JWS");
  let claims: unknown;
  try {
    claims = JSON.parse(base64urlDecode(parts[1]).toString("utf8"));
  } catch (e) {
    throw new AuthentikOidcError("invalid_token", "id_token payload is not JSON", e);
  }
  return claims as IdTokenClaims;
}

/** Fetch the provider JWKS and verify the RS256 signature of an id_token. */
export async function verifyIdToken(opts: {
  token: string;
  issuer: string;
  jwksUri: string;
  expectedAudience: string;
  expectedNonce?: string;
}): Promise<IdTokenClaims> {
  const [headerB64] = opts.token.split(".");
  let header: { kid?: string; alg?: string };
  try {
    header = JSON.parse(base64urlDecode(headerB64).toString("utf8"));
  } catch {
    throw new AuthentikOidcError("invalid_token", "id_token header is not JSON");
  }
  if (header.alg !== "RS256") {
    throw new AuthentikOidcError(
      "invalid_token",
      `unsupported id_token alg ${header.alg ?? "(missing)"} (only RS256)`,
    );
  }
  const jwks = await fetchJson<{ keys: Array<{ kid?: string; kty?: string; alg?: string }> }>(
    opts.jwksUri,
  );
  const key = (jwks.keys ?? []).find(
    (k) => k.kty === "RSA" && (!header.kid || k.kid === header.kid),
  );
  if (!key) {
    throw new AuthentikOidcError("invalid_token", `no RSA key matches kid ${header.kid ?? "any"}`);
  }

  const [rawHeader, rawPayload, rawSig] = opts.token.split(".");
  const signature = base64urlDecode(rawSig);
  const data = Buffer.from(`${rawHeader}.${rawPayload}`, "ascii");
  const publicKey = crypto.createPublicKey({ key: key as crypto.JsonWebKey, format: "jwk" });
  const valid = crypto.verify("RSA-SHA256", data, publicKey, signature);
  if (!valid) throw new AuthentikOidcError("invalid_token", "id_token signature invalid");

  const claims = parseJwtClaims(opts.token);
  if (claims.iss !== opts.issuer) {
    throw new AuthentikOidcError("invalid_token", `iss mismatch: ${claims.iss}`);
  }
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(opts.expectedAudience)) {
    throw new AuthentikOidcError("invalid_token", `aud mismatch: ${claims.aud}`);
  }
  if (typeof claims.exp === "number" && claims.exp * 1000 < Date.now()) {
    throw new AuthentikOidcError("invalid_token", "id_token expired");
  }
  if (opts.expectedNonce && claims.nonce !== opts.expectedNonce) {
    throw new AuthentikOidcError("invalid_token", "nonce mismatch");
  }
  return claims;
}

/** Full login helper: discovery -> verify the exchanged id_token. */
export async function authenticate(opts: {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  code: string;
  verifier: string;
  expectedNonce?: string;
}): Promise<{ claims: IdTokenClaims; profile: AuthentikProfile; id_token: string }> {
  const discovery = await discover(opts.issuer);
  const { id_token } = await exchangeCode(opts);
  const claims = await verifyIdToken({
    token: id_token,
    issuer: opts.issuer,
    jwksUri: discovery.jwks_uri,
    expectedAudience: opts.clientId,
    expectedNonce: opts.expectedNonce,
  });
  const groups = Array.isArray(claims.groups) ? claims.groups.map(String) : [];
  return {
    claims,
    id_token,
    profile: {
      sub: claims.sub,
      email: claims.email ?? null,
      name: claims.name ?? null,
      groups,
      isAdmin: groups.includes(env.adminGroup),
      raw: claims,
    },
  };
}
