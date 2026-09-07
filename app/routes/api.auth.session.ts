import { json, type LoaderFunctionArgs } from "@vercel/remix";
import { parseJwtClaims } from "~/lib/.server/authentik";
import {
  oidcEnv,
  readCookie,
  SESSION_COOKIE,
  verifySessionCookie,
} from "~/lib/.server/auth-session";
import type { IdTokenClaims } from "~/lib/.server/authentik";

/**
 * GET /api/auth/session — the client reads the id_token + decoded user here
 * (cookie is httpOnly) and feeds the token to Convex via `client.setAuth`.
 */
export async function loader({ request }: LoaderFunctionArgs) {
  const cfg = oidcEnv();
  const raw = readCookie(request, SESSION_COOKIE);
  if (!cfg.enabled || !raw) {
    return json({ user: null, id_token: null });
  }
  const idToken = verifySessionCookie(raw);
  if (!idToken) {
    return json({ user: null, id_token: null });
  }
  let user: IdTokenClaims | null = null;
  try {
    user = parseJwtClaims(idToken);
  } catch {
    return json({ user: null, id_token: null });
  }
  return json({ user, id_token: idToken });
}
