import { redirect, type LoaderFunctionArgs } from "@vercel/remix";
import { authorizationUrl } from "~/lib/.server/authentik";
import {
  oidcEnv,
  requestOrigin,
  setEphemeralCookie,
  STATE_COOKIE,
  VERIFIER_COOKIE,
} from "~/lib/.server/auth-session";

/**
 * GET /api/auth/start — begin the Authentik Authorization Code + PKCE flow.
 * Stashes the verifier + state in short-lived httpOnly cookies so the callback
 * can complete the exchange, then redirects to Authentik.
 */
export async function loader({ request }: LoaderFunctionArgs) {
  const cfg = oidcEnv();
  if (!cfg.enabled) {
    throw new Response("Authentik auth is not enabled", { status: 404 });
  }
  const redirectUri = `${requestOrigin(request)}/api/auth/callback`;
  const { url, verifier, state } = await authorizationUrl({
    issuer: cfg.issuer,
    clientId: cfg.clientId,
    redirectUri,
    scope: "openid profile email groups",
  });

  return redirect(url, {
    headers: {
      "Set-Cookie": [
        setEphemeralCookie(VERIFIER_COOKIE, verifier),
        setEphemeralCookie(STATE_COOKIE, state),
      ].join(", "),
    },
  });
}
