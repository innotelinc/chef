/**
 * Mode-agnostic auth for Chef.
 *
 * Upstream: WorkOS AuthKit (AuthKitProvider + ConvexProviderWithAuthKit).
 * Fork (docs/chef-auth-fork.md): Authentik Authorization Code + PKCE, with the
 * code exchange + session handled by the server (/api/auth/* routes) and the
 * id_token fed to Convex via `convex.setAuth` — convex/auth.config.ts validates
 * it against the Authentik JWKS.
 *
 * Consumers keep calling `useAuth()` from `~/lib/auth/context` and receive the
 * AuthKit-compatible shape { isLoading, user, getAccessToken, signIn, signOut }.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { AuthKitProvider, useAuth as useAuthKit } from "@workos-inc/authkit-react";

export type AuthUserLike = {
  id?: string;
  email?: string | null;
  firstName?: string | null;
  lastName?: string | null;
  name?: string | null;
  /** Authentik group memberships (from the id_token `groups` claim). */
  groups?: string[];
  profilePictureUrl?: string | null;
} & Record<string, unknown>;

export interface AuthContextValue {
  isLoading: boolean;
  user: AuthUserLike | null;
  getAccessToken: (opts?: { forceRefreshToken?: boolean }) => Promise<string | null>;
  signIn: (opts?: Record<string, unknown>) => void | Promise<void>;
  signOut: (opts?: { returnTo?: string }) => void | Promise<void>;
}

/** Minimal Convex client surface we need (setAuth/clearAuth). */
export interface ConvexAuthClient {
  setAuth(fetchToken: (args: { forceRefreshToken: boolean }) => Promise<string | null | undefined>): void;
  clearAuth(): void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}

interface SessionResponse {
  user: Record<string, unknown> | null;
  id_token: string | null;
}

function claimsToUser(claims: Record<string, unknown> | null): AuthUserLike | null {
  if (!claims || typeof claims.sub !== "string") return null;
  const c = claims as Record<string, unknown>;
  const str = (k: string): string | null =>
    typeof c[k] === "string" ? (c[k] as string) : null;
  return {
    id: c.sub as string,
    email: str("email"),
    name: str("name"),
    firstName: str("given_name"),
    lastName: str("family_name"),
    groups: Array.isArray(c.groups) ? (c.groups as string[]) : [],
    ...c,
  };
}

// ─── Authentik (fork mode) ────────────────────────────────────────────────

function AuthentikAuthProvider({
  convex,
  children,
}: {
  convex: ConvexAuthClient;
  children: ReactNode;
}) {
  const [isLoading, setIsLoading] = useState(true);
  const [user, setUser] = useState<AuthUserLike | null>(null);
  const tokenRef = useRef<string | null>(null);

  const refreshSession = useCallback(async () => {
    try {
      const res = await fetch("/api/auth/session", { headers: { Accept: "application/json" } });
      if (!res.ok) {
        setUser(null);
        tokenRef.current = null;
        return;
      }
      const data = (await res.json()) as SessionResponse;
      tokenRef.current = data.id_token;
      setUser(claimsToUser(data.user));
    } catch {
      setUser(null);
      tokenRef.current = null;
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      await refreshSession();
      if (!cancelled) setIsLoading(false);
    })();
    return () => {
      cancelled = true;
    };
  }, [refreshSession]);

  // Hand the id_token to Convex (validated against the Authentik JWKS).
  useEffect(() => {
    convex.setAuth(async ({ forceRefreshToken }) => {
      if (forceRefreshToken || !tokenRef.current) {
        try {
          const res = await fetch("/api/auth/session", { headers: { Accept: "application/json" } });
          if (res.ok) {
            const data = (await res.json()) as SessionResponse;
            tokenRef.current = data.id_token;
          }
        } catch {
          return null;
        }
      }
      return tokenRef.current;
    });
    return () => {
      convex.clearAuth();
    };
  }, [convex]);

  const value = useMemo<AuthContextValue>(
    () => ({
      isLoading,
      user,
      getAccessToken: async () => tokenRef.current,
      signIn: () => {
        window.location.assign("/api/auth/start");
      },
      signOut: async ({ returnTo } = {}) => {
        try {
          await fetch("/api/auth/signout", { method: "POST" });
        } finally {
          tokenRef.current = null;
          setUser(null);
          convex.clearAuth();
          window.location.assign(returnTo ?? "/");
        }
      },
    }),
    [isLoading, user, convex],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// ─── WorkOS AuthKit (upstream mode) ───────────────────────────────────────

function AuthKitBridge({
  convex,
  children,
}: {
  convex: ConvexAuthClient;
  children: ReactNode;
}) {
  const kit = useAuthKit();

  useEffect(() => {
    convex.setAuth(async () => (await kit.getAccessToken()) ?? null);
    return () => {
      convex.clearAuth();
    };
  }, [convex, kit]);

  const value = useMemo<AuthContextValue>(
    () => ({
      isLoading: kit.isLoading,
      user: (kit.user as AuthUserLike | null) ?? null,
      // AuthKit names its refresh option `forceRefresh`; ours is
      // `forceRefreshToken` — wrap so the shapes line up for consumers.
      getAccessToken: async () => (await kit.getAccessToken()) ?? null,
      signIn: kit.signIn,
      signOut: kit.signOut,
    }),
    [kit],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// ─── Top-level provider ───────────────────────────────────────────────────

export function AuthProvider({
  mode,
  convex,
  children,
}: {
  /** "authentik" (fork) or "workos" (upstream) — from the root loader. */
  mode: "authentik" | "workos";
  convex: ConvexAuthClient;
  children: ReactNode;
}) {
  if (mode === "authentik") {
    return <AuthentikAuthProvider convex={convex}>{children}</AuthentikAuthProvider>;
  }

  return (
    <AuthKitProvider
      clientId={import.meta.env.VITE_WORKOS_CLIENT_ID}
      redirectUri={globalThis.process.env.WORKOS_REDIRECT_URI}
      apiHostname={import.meta.env.VITE_WORKOS_API_HOSTNAME}
    >
      <AuthKitBridge convex={convex}>{children}</AuthKitBridge>
    </AuthKitProvider>
  );
}
