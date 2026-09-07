import { describe, expect, it, vi } from "vitest";
import crypto from "node:crypto";
import {
  buildAuthorizeUrl,
  decodeIdToken,
  discoverTokenEndpoint,
  exchangeCode,
  generateCodeChallenge,
  generateCodeVerifier,
  generateState,
} from "./oidc";

const CFG = {
  issuerUrl: "https://auth.cerulean.innotel.us/application/o/atlas-chef/",
  clientId: "atlas-chef",
  redirectUri: "https://chef.innotel.us/api/auth/callback",
  state: "state-abc",
};

function makeJwt(claims: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const sig = crypto
    .createHmac("sha256", "test-secret")
    .update(`${header}.${payload}`)
    .digest("base64url");
  return `${header}.${payload}.${sig}`;
}

describe("PKCE", () => {
  it("generates a spec-shaped code verifier", () => {
    const v = generateCodeVerifier();
    expect(v.length).toBeGreaterThanOrEqual(43);
    expect(v.length).toBeLessThanOrEqual(128);
    expect(v).toMatch(/^[A-Za-z0-9\-._~]+$/);
    expect(generateCodeVerifier()).not.toBe(v);
  });

  it("derives the S256 code challenge deterministically", async () => {
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    await expect(generateCodeChallenge(verifier)).resolves.toBe(expected);
  });

  it("generates distinct state values", () => {
    expect(generateState()).toMatch(/^[A-Za-z0-9\-_]+$/);
    expect(generateState()).not.toBe(generateState());
  });
});

describe("buildAuthorizeUrl", () => {
  it("builds an authorize URL with PKCE parameters", async () => {
    const challenge = await generateCodeChallenge("verifier");
    const url = new URL(buildAuthorizeUrl({ ...CFG, codeChallenge: challenge }));
    expect(url.origin + url.pathname).toBe(
      "https://auth.cerulean.innotel.us/application/o/atlas-chef/authorize/",
    );
    expect(url.searchParams.get("client_id")).toBe("atlas-chef");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("redirect_uri")).toBe(CFG.redirectUri);
    expect(url.searchParams.get("state")).toBe("state-abc");
    expect(url.searchParams.get("code_challenge")).toBe(challenge);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("scope")).toBe("openid email profile");
  });

  it("tolerates an issuer without a trailing slash", async () => {
    const challenge = await generateCodeChallenge("verifier");
    const url = buildAuthorizeUrl({ ...CFG, issuerUrl: CFG.issuerUrl.slice(0, -1), codeChallenge: challenge });
    expect(url).toContain("/application/o/atlas-chef/authorize/");
  });
});

describe("exchangeCode", () => {
  it("POSTs the code + verifier and returns the token response", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id_token: "abc.def.ghi", token_type: "Bearer" }),
    });
    const res = await exchangeCode(
      "https://auth.example/token/",
      { clientId: CFG.clientId, redirectUri: CFG.redirectUri, code: "c0de", codeVerifier: "v3r" },
      fetchMock as unknown as typeof fetch,
    );
    expect(res.id_token).toBe("abc.def.ghi");
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.method).toBe("POST");
    const body = init.body as URLSearchParams;
    expect(body.get("grant_type")).toBe("authorization_code");
    expect(body.get("code_verifier")).toBe("v3r");
    expect(body.get("code")).toBe("c0de");
  });

  it("throws with a readable error on a failed exchange", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      statusText: "Bad Request",
      text: async () => "invalid_grant",
    });
    await expect(
      exchangeCode(
        "https://auth.example/token/",
        { clientId: "c", redirectUri: "r", code: "x", codeVerifier: "y" },
        fetchMock as unknown as typeof fetch,
      ),
    ).rejects.toThrow(/400.*invalid_grant/s);
  });
});

describe("discoverTokenEndpoint", () => {
  it("reads the token endpoint from the discovery document", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ token_endpoint: "https://auth.example/token/" }),
    });
    await expect(
      discoverTokenEndpoint("https://auth.example/application/o/app/", fetchMock as unknown as typeof fetch),
    ).resolves.toBe("https://auth.example/token/");
  });

  it("throws when the discovery document lacks a token endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
    await expect(
      discoverTokenEndpoint("https://auth.example/issuer", fetchMock as unknown as typeof fetch),
    ).rejects.toThrow(/no token_endpoint/);
  });
});

describe("decodeIdToken", () => {
  it("decodes valid claims", () => {
    const token = makeJwt({
      sub: "user-1",
      email: "op@innotel.us",
      name: "Operator",
      groups: ["atlas-admins"],
    });
    const claims = decodeIdToken(token);
    expect(claims.sub).toBe("user-1");
    expect(claims.email).toBe("op@innotel.us");
    expect(claims.groups).toContain("atlas-admins");
  });

  it("rejects non-JWT input", () => {
    expect(() => decodeIdToken("not-a-jwt")).toThrow(/JWT/);
  });

  it("rejects a token without a sub claim", () => {
    const token = makeJwt({ email: "no-sub@example.com" });
    expect(() => decodeIdToken(token)).toThrow(/`sub`/);
  });
});
