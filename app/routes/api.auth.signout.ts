import { json, type ActionFunctionArgs } from "@vercel/remix";

/**
 * POST /api/auth/signout — clear the httpOnly session cookie. The client also
 * calls `convex.clearAuth()` so in-flight Convex auth stops.
 *
 * Server helpers are imported dynamically inside `action`: a top-level import
 * of `~/lib/.server/auth-session` makes `remix vite:build` treat this route
 * as client-referencing a server-only module (resource routes are still part
 * of the client route graph). The dynamic import lives entirely in the
 * server-side `action` body.
 */
export async function action({ request }: ActionFunctionArgs) {
  void request; // keep the signature symmetric with the other auth routes
  const { clearSessionCookie } = await import("~/lib/.server/auth-session");
  return json({ ok: true }, { headers: { "Set-Cookie": clearSessionCookie() } });
}
