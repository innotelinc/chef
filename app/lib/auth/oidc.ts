/**
 * Browser-side OIDC helpers for the Authentik Authorization Code + PKCE grant
 * (docs/chef-auth-fork.md stage 3b). Pure functions — unit-tested with vitest.
 *
 * Flow (fork mode):
 *   1. signIn() redirects to the Authentik authorize URL built by
 *      buildAuthorizeUrl() with a PKCE challenge.
 *   2. Authentik redirects to `/api/auth/callback?code=…&state=…`, where the
 *      server exchanges the code (app/lib/.server/authentik.ts) and stores the
 *      id_token in a session cookie.
 *   3. The client reads the id_token back and hands it to Convex via
 *      `client.setAuth(...)`; convex/auth.config.ts validates it against the
 *      Authentik JWKS (customJwt provider).
 */

export interface OidcConfig {
  /** e.g. https://auth.cerulean.innotel.us/application/o/atlas-chef/ */
  issuerUrl: string;
  clientId: string;
  redirectUri: string;
  /** Opaque anti-CSRF value bound to the state parameter. */
  state: string;
  scope?: string;
}

export interface OidcTokenResponse {
  id_token: string;
  access_token?: string;
  token_type?: string;
  expires_in?: number;
}

export interface IdTokenClaims {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  preferred_username?: string;
  groups?: string[];
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function base64UrlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Generate `length` random bytes (crypto.getRandomValues). */
export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

/** OIDC `code_verifier` (43–128 unreserved chars). */
export function generateCodeVerifier(): string {
  return base64UrlEncode(randomBytes(48)).slice(0, 64);
}

/** OIDC `code_challenge` = base64url(SHA-256(code_verifier)). */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(verifier));
  return base64UrlEncode(new Uint8Array(digest));
}

/** A new opaque state value (anti-CSRF). */
export function generateState(): string {
  return base64UrlEncode(randomBytes(24));
}

function withTrailingSlash(url: string): string {
  return url.endsWith("/") ? url : `${url}/`;
}

/**
 * Authorize URL for the Authentik application issuer:
 * `<issuer>/authorize/` per OIDC discovery. Falls back to
 * `/.well-known/openid-configuration` discovery when `discovery` is true.
 */
export function buildAuthorizeUrl(
  config: OidcConfig & { codeChallenge: string },
): string {
  const issuer = withTrailingSlash(config.issuerUrl);
  const authorize = new URL(`${issuer}authorize/`);
  authorize.searchParams.set("client_id", config.clientId);
  authorize.searchParams.set("redirect_uri", config.redirectUri);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("scope", config.scope ?? "openid email profile");
  authorize.searchParams.set("state", config.state);
  authorize.searchParams.set("code_challenge", config.codeChallenge);
  authorize.searchParams.set("code_challenge_method", "S256");
  return authorize.toString();
}

/** Exchange the authorization code at the token endpoint (PKCE). */
export async function exchangeCode(
  tokenEndpoint: string,
  params: {
    clientId: string;
    redirectUri: string;
    code: string;
    codeVerifier: string;
  },
  fetchImpl: typeof fetch = fetch,
): Promise<OidcTokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: params.clientId,
    redirect_uri: params.redirectUri,
    code: params.code,
    code_verifier: params.codeVerifier,
  });
  const res = await fetchImpl(tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `Token exchange failed: ${res.status} ${res.statusText}${text ? ` — ${text.slice(0, 200)}` : ""}`,
    );
  }
  return (await res.json()) as OidcTokenResponse;
}

/** Fetch the token endpoint from the provider's OIDC discovery document. */
export async function discoverTokenEndpoint(
  issuerUrl: string,
  fetchImpl: typeof fetch = fetch,
): Promise<string> {
  const res = await fetchImpl(
    `${withTrailingSlash(issuerUrl)}.well-known/openid-configuration`,
  );
  if (!res.ok) {
    throw new Error(`OIDC discovery failed: ${res.status} ${res.statusText}`);
  }
  const doc = (await res.json()) as { token_endpoint?: string };
  if (!doc.token_endpoint) {
    throw new Error("OIDC discovery document has no token_endpoint");
  }
  return doc.token_endpoint;
}

/** Decode (and structurally validate) an id_token JWT without verifying the signature. */
export function decodeIdToken(idToken: string): IdTokenClaims {
  const parts = idToken.split(".");
  if (parts.length !== 3) {
    throw new Error("id_token is not a JWT (expected 3 dot-separated parts)");
  }
  let payload: string;
  try {
    payload = decoder.decode(
      Uint8Array.from(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")), (c) =>
        c.charCodeAt(0),
      ),
    );
  } catch {
    throw new Error("id_token payload is not valid base64url");
  }
  let claims: IdTokenClaims;
  try {
    claims = JSON.parse(payload) as IdTokenClaims;
  } catch {
    throw new Error("id_token payload is not valid JSON");
  }
  if (typeof claims.sub !== "string" || claims.sub.length === 0) {
    throw new Error("id_token has no `sub` claim");
  }
  return claims;
}
