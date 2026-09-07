/**
 * Convex Auth trust anchor for Chef.
 *
 * Upstream trusts Convex cloud's WorkOS-backed user management (issuer +
 * JWKS under apiauth.convex.dev). The Atlas fork (docs/chef-auth-fork.md,
 * stage 3b/3c) points the same `customJwt` provider at Cerulean Authentik
 * instead — Convex Auth only ever verifies RS256 id_tokens against the
 * configured JWKS, so the provider shape is identical.
 *
 * Selection is env-driven so behavior is unchanged until the fork's client
 * side (PKCE Authorization Code grant against Authentik, see
 * app/lib/.server/authentik.ts) actually lands:
 *   - CHEF_OIDC_ISSUER_URL set  → Authentik (application issuer; JWKS is
 *     `<issuer>/jwks/`, e.g. https://auth.cerulean.innotel.us/application/o/atlas-chef/)
 *   - otherwise                 → upstream WorkOS-backed Convex cloud
 */
const workosClientId = process.env.WORKOS_CLIENT_ID;
const authentikIssuer = process.env.CHEF_OIDC_ISSUER_URL?.replace(/\/+$/, "");

const provider = authentikIssuer
  ? {
      type: "customJwt" as const,
      issuer: authentikIssuer,
      algorithm: "RS256" as const,
      jwks: `${authentikIssuer}/jwks/`,
      applicationID: process.env.CHEF_OIDC_CLIENT_ID ?? "atlas-chef",
    }
  : {
      type: "customJwt" as const,
      issuer: `https://apiauth.convex.dev/user_management/${workosClientId}`,
      algorithm: "RS256" as const,
      jwks: `https://apiauth.convex.dev/sso/jwks/${workosClientId}`,
      applicationID: workosClientId,
    };

export default {
  providers: [provider],
};
