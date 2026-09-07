/**
 * Unit tests for the Authentik OIDC client (stage 3b). Runs with tsx against
 * node:test — no network: discovery/token/JWKS endpoints are mocked, and the
 * id_token is signed with a locally generated RSA keypair.
 *
 * Run:  pnpm exec tsx --test app/lib/.server/authentik.test.ts
 */

import assert from "node:assert/strict";
import crypto from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  authorizationUrl,
  authenticate,
  AuthentikOidcError,
  base64urlDecode,
  base64urlEncode,
  exchangeCode,
  parseJwtClaims,
  pkce,
  verifyIdToken,
} from "./authentik";

const ISSUER = "https://auth.cerulean.innotel.us/application/o/atlas-chef/";
const CLIENT_ID = "atlas-chef";
const REDIRECT = "https://chef.innotel.us/api/auth/callback";

function makeKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const jwk = publicKey.export({ format: "jwk" });
  return { publicKey, privateKey, jwk: { ...jwk, kid: "test-key-1", alg: "RS256" } };
}

function signIdToken(privateKey: crypto.KeyObject, claims: object): string {
  const header = base64urlEncode(JSON.stringify({ alg: "RS256", kid: "test-key-1", typ: "JWT" }));
  const payload = base64urlEncode(JSON.stringify({ iss: ISSUER, aud: CLIENT_ID, exp: Math.floor(Date.now() / 1000) + 3600, ...claims }));
  const data = Buffer.from(`${header}.${payload}`, "ascii");
  const sig = crypto.sign("RSA-SHA256", data, privateKey);
  return `${header}.${payload}.${base64urlEncode(sig)}`;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => vi.unstubAllGlobals());

describe("pkce", () => {
  it("produces a verifier/challenge pair matching RFC 7636 S256", () => {
    const { verifier, challenge } = pkce();
    assert.ok(verifier.length >= 43 && verifier.length <= 128);
    const expected = base64urlEncode(crypto.createHash("sha256").update(verifier).digest());
    assert.equal(challenge, expected);
  });
});

describe("authorizationUrl", () => {
  it("includes code challenge, state, and requested scopes", () => {
    const { url, verifier, state } = authorizationUrl({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT,
    });
    const u = new URL(url);
    expect(url).toContain(`${ISSUER}authorize/`);
    assert.equal(u.searchParams.get("response_type"), "code");
    assert.equal(u.searchParams.get("client_id"), CLIENT_ID);
    assert.equal(u.searchParams.get("redirect_uri"), REDIRECT);
    assert.equal(u.searchParams.get("code_challenge_method"), "S256");
    assert.ok(u.searchParams.get("code_challenge"));
    assert.ok(u.searchParams.get("state"));
    assert.ok(verifier && state);
    const challenge = base64urlEncode(crypto.createHash("sha256").update(verifier).digest());
    assert.equal(u.searchParams.get("code_challenge"), challenge);
  });
});

describe("verifyIdToken", () => {
  const { privateKey, jwk } = makeKeypair();

  it("accepts a valid RS256 id_token with matching kid/iss/aud", async () => {
    vi.stubGlobal("fetch", async () => jsonResponse({ keys: [jwk] }));
    const token = signIdToken(privateKey, { sub: "user-1", email: "a@x.io" });
    const claims = await verifyIdToken({
      token,
      issuer: ISSUER,
      jwksUri: `${ISSUER}jwks`,
      expectedAudience: CLIENT_ID,
    });
    assert.equal(claims.sub, "user-1");
    assert.equal(claims.email, "a@x.io");
  });

  it("rejects a token signed by an unknown key", async () => {
    const other = makeKeypair();
    vi.stubGlobal("fetch", async () => jsonResponse({ keys: [other.jwk] }));
    const token = signIdToken(privateKey, { sub: "user-1" });
    await assert.rejects(
      verifyIdToken({ token, issuer: ISSUER, jwksUri: `${ISSUER}jwks`, expectedAudience: CLIENT_ID }),
      (e: unknown) => e instanceof AuthentikOidcError && e.code === "invalid_token",
    );
  });

  it("rejects a tampered payload (signature invalid)", async () => {
    vi.stubGlobal("fetch", async () => jsonResponse({ keys: [jwk] }));
    const token = signIdToken(privateKey, { sub: "user-1" });
    const [h, p, s] = token.split(".");
    const tampered = `${h}.${base64urlEncode(Buffer.from(JSON.stringify({ sub: "attacker" })))}.${s}`;
    await assert.rejects(
      verifyIdToken({ token: tampered, issuer: ISSUER, jwksUri: `${ISSUER}jwks`, expectedAudience: CLIENT_ID }),
      /signature invalid/,
    );
  });

  it("rejects wrong audience", async () => {
    vi.stubGlobal("fetch", async () => jsonResponse({ keys: [jwk] }));
    const token = signIdToken(privateKey, { sub: "user-1" });
    await assert.rejects(
      verifyIdToken({ token, issuer: ISSUER, jwksUri: `${ISSUER}jwks`, expectedAudience: "other-app" }),
      /aud mismatch/,
    );
  });

  it("rejects an expired token", async () => {
    vi.stubGlobal("fetch", async () => jsonResponse({ keys: [jwk] }));
    const claims = { sub: "user-1", exp: Math.floor(Date.now() / 1000) - 10 };
    const token = signIdToken(privateKey, claims);
    await assert.rejects(
      verifyIdToken({ token, issuer: ISSUER, jwksUri: `${ISSUER}jwks`, expectedAudience: CLIENT_ID }),
      /expired/,
    );
  });
});

describe("exchangeCode / authenticate", () => {
  const { privateKey, jwk } = makeKeypair();

  it("maps Authentik groups onto the profile and admin flag", async () => {
    const calls: string[] = [];
    vi.stubGlobal("fetch", async (input: string | URL | Request) => {
      const url = String(input);
      calls.push(url);
      if (url.endsWith("/.well-known/openid-configuration")) {
        return jsonResponse({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}authorize/`,
          token_endpoint: `${ISSUER}token/`,
          jwks_uri: `${ISSUER}jwks`,
        });
      }
      if (url.endsWith("/token/")) {
        const token = signIdToken(privateKey, {
          sub: "user-9",
          email: "dev@innotel.us",
          name: "Dev User",
          groups: ["users", "atlas-admins"],
        });
        return jsonResponse({ id_token: token });
      }
      if (url.endsWith("/jwks")) return jsonResponse({ keys: [jwk] });
      throw new Error(`unexpected fetch: ${url}`);
    });

    const result = await authenticate({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      clientSecret: "secret",
      redirectUri: REDIRECT,
      code: "auth-code",
      verifier: "x".repeat(64),
    });
    assert.equal(result.profile.sub, "user-9");
    assert.equal(result.profile.email, "dev@innotel.us");
    assert.deepEqual(result.profile.groups, ["users", "atlas-admins"]);
    assert.equal(result.profile.isAdmin, true);
    assert.ok(calls.some((c) => c.includes("openid-configuration")));
    assert.ok(calls.some((c) => c.includes("/token/")));
  });

  it("surfaces token-endpoint failures as AuthentikOidcError code=token", async () => {
    vi.stubGlobal("fetch", async (input: string | URL | Request) => {
      const url = String(input);
      if (url.endsWith("/.well-known/openid-configuration")) {
        return jsonResponse({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}authorize/`,
          token_endpoint: `${ISSUER}token/`,
          jwks_uri: `${ISSUER}jwks`,
        });
      }
      return jsonResponse({ error: "invalid_grant" }, 400);
    });
    await assert.rejects(
      exchangeCode({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        clientSecret: "secret",
        redirectUri: REDIRECT,
        code: "bad",
        verifier: "y".repeat(64),
      }),
      (e: unknown) => e instanceof AuthentikOidcError && e.code === "token",
    );
  });
});

describe("parseJwtClaims", () => {
  it("round-trips base64url payloads", () => {
    const raw = "hello wörld ✓";
    assert.equal(base64urlDecode(base64urlEncode(raw)).toString("utf8"), raw);
    const claims = { sub: "s1", email: "a@b.c" };
    const token = `${base64urlEncode("{}")}.${base64urlEncode(JSON.stringify(claims))}.sig`;
    assert.deepEqual(parseJwtClaims(token), { ...claims });
  });
});
