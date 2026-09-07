import { redirect, type LoaderFunctionArgs } from "@vercel/remix";
import { exchangeCode, parseJwtClaims } from "~/lib/.server/authentik";
import {
  clearEphemeralCookie,
  oidcEnv,
  readCookie,
  requestOrigin,
  setSessionCookie,
  STATE_COOKIE,
  VERIFIER_COOKIE,
} from "~/lib/.server/auth-session";

/**
 * GET /api/auth/callback — Authentik redirect target (registered as
 * `chef.<zone>/api/auth/callback` for the `atlas-chef` OIDC client).
 * Exchanges the code server-side, verifies the state cookie, and stores the
 * id_token in the httpOnly session cookie.
 */
export async function loader({ request }: LoaderFunctionArgs) {
  const cfg = oidcEnv();
  if (!cfg.enabled) {
    throw new Response("Authentik auth is not enabled", { status: 404 });
  }

  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const expectedState = readCookie(request, STATE_COOKIE);
  const verifier = readCookie(request, VERIFIER_COOKIE);

  // Always clear the ephemeral cookies — they are single-use.
  const clearCookies = [
    clearEphemeralCookie(STATE_COOKIE),
    clearEphemeralCookie(VERIFIER_COOKIE),
  ];

  if (!code || !state || !verifier) {
    return redirect("/", {
      headers: { "Set-Cookie": clearCookies.join(", ") },
    });
  }
  if (!expectedState || state !== expectedState) {
    return redirect("/?auth=state_mismatch", {
      headers: { "Set-Cookie": clearCookies.join(", ") },
    });
  }

  const redirectUri = `${requestOrigin(request)}/api/auth/callback`;
  const { id_token } = await exchangeCode({
    issuer: cfg.issuer,
    clientId: cfg.clientId,
    clientSecret: cfg.clientSecret,
    redirectUri,
    code,
    verifier,
  });

  // Structural sanity check on the token we just minted the session from.
  parseJwtClaims(id_token);

  return redirect("/", {
    headers: {
      "Set-Cookie": [setSessionCookie(id_token), ...clearCookies].join(", "),
    },
  });
}
