import { json, type ActionFunctionArgs } from "@vercel/remix";
import { clearSessionCookie, oidcEnv } from "~/lib/.server/auth-session";

/**
 * POST /api/auth/signout — clear the httpOnly session cookie. The client also
 * calls `convex.clearAuth()` so in-flight Convex auth stops.
 */
export async function action({ request }: ActionFunctionArgs) {
  void request;
  void oidcEnv; // route exists only in fork mode; upstream uses AuthKit signOut
  return json({ ok: true }, { headers: { "Set-Cookie": clearSessionCookie() } });
}
