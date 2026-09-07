import {
  internalAction,
  internalMutation,
  internalQuery,
  mutation,
  query,
  type ActionCtx,
  type MutationCtx,
} from "./_generated/server";
import { ConvexError, v } from "convex/values";
import { getChatByIdOrUrlIdEnsuringAccess } from "./messages";
import { internal } from "./_generated/api";
import type { Id } from "./_generated/dataModel";

/** Fork 3b.2 — client-visible mode switch: true when this backend provisions
 * per-app backends through chef-provisioner instead of the hosted control
 * plane (i.e. `CHEF_PROVISION_URL` is set on the Convex backend). */
export const isLocalProvisioningEnabled = query({
  args: {},
  returns: v.boolean(),
  handler: () => localProvisioningEnabled(),
});

export const hasConnectedConvexProject = query({
  args: {
    sessionId: v.id("sessions"),
    chatId: v.string(),
  },
  handler: async (ctx, args) => {
    const chat = await getChatByIdOrUrlIdEnsuringAccess(ctx, { id: args.chatId, sessionId: args.sessionId });
    return chat?.convexProject !== undefined;
  },
});

export const loadConnectedConvexProjectCredentials = query({
  args: {
    sessionId: v.id("sessions"),
    chatId: v.string(),
  },
  returns: v.union(
    v.object({
      kind: v.literal("connected"),
      projectSlug: v.string(),
      teamSlug: v.string(),
      deploymentUrl: v.string(),
      deploymentName: v.string(),
      adminKey: v.string(),
      warningMessage: v.optional(v.string()),
    }),
    v.object({
      kind: v.literal("connecting"),
    }),
    v.object({
      kind: v.literal("failed"),
      errorMessage: v.string(),
    }),
    v.null(),
  ),
  handler: async (ctx, args) => {
    const chat = await getChatByIdOrUrlIdEnsuringAccess(ctx, { id: args.chatId, sessionId: args.sessionId });
    if (!chat) {
      return null;
    }
    const project = chat.convexProject;
    if (project === undefined) {
      return null;
    }
    if (project.kind === "connecting") {
      return { kind: "connecting" } as const;
    }
    if (project.kind === "failed") {
      return { kind: "failed", errorMessage: project.errorMessage } as const;
    }
    const credentials = await ctx.db
      .query("convexProjectCredentials")
      .withIndex("bySlugs", (q) => q.eq("teamSlug", project.teamSlug).eq("projectSlug", project.projectSlug))
      .first();
    if (!credentials) {
      return null;
    }
    return {
      kind: "connected",
      projectSlug: project.projectSlug,
      teamSlug: project.teamSlug,
      deploymentUrl: project.deploymentUrl,
      deploymentName: project.deploymentName,
      adminKey: credentials.projectDeployKey,
      warningMessage: project.warningMessage,
    } as const;
  },
});

const CHECK_CONNECTION_DEADLINE_MS = 15000;

export const startProvisionConvexProject = mutation({
  args: {
    sessionId: v.id("sessions"),
    chatId: v.string(),
    projectInitParams: v.optional(
      v.object({
        teamSlug: v.string(),
        workosAccessToken: v.string(),
      }),
    ),
  },
  handler: async (ctx, args) => {
    await startProvisionConvexProjectHelper(ctx, args);
  },
});

export async function startProvisionConvexProjectHelper(
  ctx: MutationCtx,
  args: {
    sessionId: Id<"sessions">;
    chatId: string;
    projectInitParams?: {
      teamSlug: string;
      workosAccessToken: string;
    };
  },
): Promise<void> {
  const chat = await getChatByIdOrUrlIdEnsuringAccess(ctx, { id: args.chatId, sessionId: args.sessionId });
  if (!chat) {
    throw new ConvexError({ code: "NotAuthorized", message: "Chat not found" });
  }
  const session = await ctx.db.get("sessions", args.sessionId);
  if (!session) {
    console.error(`Session not found: ${args.sessionId}`);
    throw new ConvexError({ code: "NotAuthorized", message: "Chat not found" });
  }
  if (session.memberId === undefined) {
    throw new ConvexError({ code: "NotAuthorized", message: "Must be logged in to connect a project" });
  }
  // Fork 3b.2 — deployment-per-app: when CHEF_PROVISION_URL is set on this
  // backend, provisioning goes through chef-provisioner (one convex-backend
  // container per app) and needs no team or WorkOS token, so callers omit
  // projectInitParams.
  if (localProvisioningEnabled()) {
    await startProvisionLocalProjectHelper(ctx, {
      sessionId: args.sessionId,
      chatId: args.chatId,
    });
    return;
  }
  // OAuth flow
  if (args.projectInitParams === undefined) {
    console.error(`Must provide projectInitParams for oauth: ${args.sessionId}`);
    throw new ConvexError({ code: "NotAuthorized", message: "Invalid flow for connecting a project" });
  }

  await ctx.scheduler.runAfter(0, internal.convexProjects.connectConvexProjectForOauth, {
    sessionId: args.sessionId,
    chatId: args.chatId,
    accessToken: args.projectInitParams.workosAccessToken,
    teamSlug: args.projectInitParams.teamSlug,
  });
  const jobId = await ctx.scheduler.runAfter(CHECK_CONNECTION_DEADLINE_MS, internal.convexProjects.checkConnection, {
    sessionId: args.sessionId,
    chatId: args.chatId,
  });
  await ctx.db.patch("chats", chat._id, { convexProject: { kind: "connecting", checkConnectionJobId: jobId } });
  return;
}

export const recordProvisionedConvexProjectCredentials = internalMutation({
  args: {
    sessionId: v.id("sessions"),
    chatId: v.string(),
    projectSlug: v.string(),
    teamSlug: v.optional(v.string()),
    projectDeployKey: v.string(),
    deploymentUrl: v.string(),
    deploymentName: v.string(),
    warningMessage: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const teamSlug = args.teamSlug ?? "demo-team";
    await ctx.db.insert("convexProjectCredentials", {
      projectSlug: args.projectSlug,
      teamSlug,
      projectDeployKey: args.projectDeployKey,
    });
    const chat = await getChatByIdOrUrlIdEnsuringAccess(ctx, { id: args.chatId, sessionId: args.sessionId });
    if (!chat) {
      console.error(`Chat not found: ${args.chatId}, sessionId: ${args.sessionId}`);
      return;
    }
    if (chat.convexProject?.kind === "connecting") {
      const jobId = chat.convexProject.checkConnectionJobId;
      if (jobId) {
        await ctx.scheduler.cancel(jobId);
      }
    }
    await ctx.db.patch("chats", chat._id, {
      convexProject: {
        kind: "connected",
        projectSlug: args.projectSlug,
        teamSlug,
        deploymentUrl: args.deploymentUrl,
        deploymentName: args.deploymentName,
        warningMessage: args.warningMessage,
      },
    });
  },
});

const TOTAL_WAIT_TIME_MS = 5000;
const WAIT_TIME_MS = 500;

export const connectConvexProjectForOauth = internalAction({
  args: {
    sessionId: v.id("sessions"),
    chatId: v.string(),
    accessToken: v.string(),
    teamSlug: v.string(),
  },
  handler: async (ctx, args) => {
    await _connectConvexProjectForMember(ctx, {
      sessionId: args.sessionId,
      chatId: args.chatId,
      accessToken: args.accessToken,
      teamSlug: args.teamSlug,
    })
      .then(async (data) => {
        await ctx.runMutation(internal.convexProjects.recordProvisionedConvexProjectCredentials, {
          sessionId: args.sessionId,
          chatId: args.chatId,
          projectSlug: data.projectSlug,
          teamSlug: args.teamSlug,
          projectDeployKey: data.projectDeployKey,
          deploymentUrl: data.deploymentUrl,
          deploymentName: data.deploymentName,
          warningMessage: data.warningMessage,
        });
      })
      .catch(async (error) => {
        console.error(`Error connecting convex project: ${error.message}`);
        const errorMessage = error instanceof ConvexError ? error.data.message : "Unexpected error";
        await ctx.runMutation(internal.convexProjects.recordFailedConvexProjectConnection, {
          sessionId: args.sessionId,
          chatId: args.chatId,
          errorMessage,
        });
      });
  },
});

async function _connectConvexProjectForMember(
  ctx: ActionCtx,
  args: {
    sessionId: Id<"sessions">;
    chatId: string;
    accessToken: string;
    teamSlug: string;
  },
): Promise<{
  projectSlug: string;
  teamSlug: string;
  deploymentUrl: string;
  deploymentName: string;
  projectDeployKey: string;
  warningMessage: string | undefined;
}> {
  const bigBrainHost = ensureEnvVar("BIG_BRAIN_HOST");
  let projectName: string | null = null;
  let timeElapsed = 0;
  // Project names get set via the first message from the LLM, so best effort
  // get the name and use it to create the project.
  while (timeElapsed < TOTAL_WAIT_TIME_MS) {
    projectName = await ctx.runQuery(internal.convexProjects.getProjectName, {
      sessionId: args.sessionId,
      chatId: args.chatId,
    });
    if (projectName) {
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, WAIT_TIME_MS));
    timeElapsed += WAIT_TIME_MS;
  }
  projectName = projectName ?? "My Project (Chef)";
  const response = await fetch(`${bigBrainHost}/api/create_project`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${args.accessToken}`,
    },
    body: JSON.stringify({
      team: args.teamSlug,
      projectName,
      deploymentType: "dev",
    }),
  });
  if (!response.ok) {
    const text = await response.text();
    const defaultProvisioningError = new ConvexError({
      code: "ProvisioningError",
      message: text.includes("SSORequired")
        ? "You must log in with Single Sign-on to access this team."
        : `Failed to create project: ${response.status}`,
      details: text,
    });
    if (response.status !== 400) {
      throw defaultProvisioningError;
    }
    let data: { code?: string; message?: string } | null = null;
    try {
      data = JSON.parse(text);
    } catch (_e) {
      throw defaultProvisioningError;
    }

    // Special case this error since it's probably semi-common
    if (data !== null && data.code === "ProjectQuotaReached" && typeof data.message === "string") {
      throw new ConvexError({
        code: "ProvisioningError",
        message: `Failed to create project: ProjectQuotaReached: ${data.message}`,
        details: text,
      });
    }
    throw defaultProvisioningError;
  }
  const data: {
    projectSlug: string;
    projectId: number;
    teamSlug: string;
    deploymentName: string;
    // This is in fact the dev URL
    prodUrl: string;
    adminKey: string;
    projectsRemaining: number;
  } = await response.json();

  const projectDeployKeyResponse = await fetch(`${bigBrainHost}/api/dashboard/authorize`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${args.accessToken}`,
    },
    body: JSON.stringify({
      authn_token: args.accessToken,
      projectId: data.projectId,
      oauthApp: {
        clientId: ensureEnvVar("CONVEX_OAUTH_CLIENT_ID"),
        clientSecret: ensureEnvVar("CONVEX_OAUTH_CLIENT_SECRET"),
      },
    }),
  });
  if (!projectDeployKeyResponse.ok) {
    const text = await projectDeployKeyResponse.text();
    throw new ConvexError({
      code: "ProvisioningError",
      message: text.includes("SSORequired")
        ? "You must log in with Single Sign-on to access this team."
        : `Failed to create project deploy key: ${projectDeployKeyResponse.status}`,
      details: text,
    });
  }
  const projectDeployKeyData: { accessToken: string } = await projectDeployKeyResponse.json();
  const projectDeployKey = `project:${args.teamSlug}:${data.projectSlug}|${projectDeployKeyData.accessToken}`;
  const warningMessage =
    data.projectsRemaining <= 2 ? `You have ${data.projectsRemaining} projects remaining on this team.` : undefined;

  return {
    projectSlug: data.projectSlug,
    teamSlug: args.teamSlug,
    deploymentUrl: data.prodUrl,
    deploymentName: data.deploymentName,
    projectDeployKey,
    warningMessage,
  };
}

export const recordFailedConvexProjectConnection = internalMutation({
  args: {
    sessionId: v.id("sessions"),
    chatId: v.string(),
    errorMessage: v.string(),
  },
  handler: async (ctx, args) => {
    const chat = await getChatByIdOrUrlIdEnsuringAccess(ctx, { id: args.chatId, sessionId: args.sessionId });
    if (!chat) {
      console.error(`Chat not found: ${args.chatId}, sessionId: ${args.sessionId}`);
      return;
    }
    if (chat.convexProject?.kind === "connecting") {
      const jobId = chat.convexProject.checkConnectionJobId;
      if (jobId) {
        await ctx.scheduler.cancel(jobId);
      }
    }
    await ctx.db.patch("chats", chat._id, {
      convexProject: { kind: "failed", errorMessage: args.errorMessage },
    });
  },
});

export const checkConnection = internalMutation({
  args: {
    sessionId: v.id("sessions"),
    chatId: v.string(),
  },
  handler: async (ctx, args) => {
    const chat = await getChatByIdOrUrlIdEnsuringAccess(ctx, { id: args.chatId, sessionId: args.sessionId });
    if (!chat) {
      console.error(`Chat not found: ${args.chatId}, sessionId: ${args.sessionId}`);
      return;
    }
    if (chat.convexProject?.kind !== "connecting") {
      return;
    }
    await ctx.db.patch("chats", chat._id, {
      convexProject: { kind: "failed", errorMessage: "Failed to connect to project" },
    });
  },
});

export const getProjectName = internalQuery({
  args: {
    sessionId: v.id("sessions"),
    chatId: v.string(),
  },
  returns: v.union(v.string(), v.null()),
  handler: async (ctx, args) => {
    const chat = await getChatByIdOrUrlIdEnsuringAccess(ctx, { id: args.chatId, sessionId: args.sessionId });
    if (!chat) {
      throw new ConvexError({ code: "NotAuthorized", message: "Chat not found" });
    }
    return chat.urlId ?? null;
  },
});

export const disconnectConvexProject = mutation({
  args: {
    sessionId: v.id("sessions"),
    chatId: v.string(),
  },
  handler: async (ctx, args) => {
    const chat = await getChatByIdOrUrlIdEnsuringAccess(ctx, { id: args.chatId, sessionId: args.sessionId });
    if (!chat) {
      throw new ConvexError({ code: "NotAuthorized", message: "Chat not found" });
    }
    await ctx.db.patch("chats", chat._id, { convexProject: undefined });
  },
});

// ── Fork 3b.2 — local provisioning (deployment-per-app) ─────────────────────
// When CHEF_PROVISION_URL is set on the Convex backend, projects are created
// by the chef-provisioner service (one convex-backend container per app,
// chef-provisioner/server.mjs in the atlas repo) instead of the hosted
// control plane. No team/workos token is involved: ownership comes from the
// Authentik identity already bound to the session.
export function localProvisioningEnabled() {
  return Boolean(process.env.CHEF_PROVISION_URL);
}

function provisionRequestHeaders() {
  const token = process.env.CHEF_PROVISION_TOKEN ?? "";
  return {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

/** Create (or return) the per-app backend via the provisioner. */
export const provisionLocalBackend = internalAction({
  args: {
    projectSlug: v.string(),
    projectName: v.string(),
  },
  handler: async (_ctx, args) => {
    const base = ensureEnvVar("CHEF_PROVISION_URL").replace(/\/+$/, "");
    const response = await fetch(`${base}/projects`, {
      method: "POST",
      headers: provisionRequestHeaders(),
      body: JSON.stringify({ slug: args.projectSlug, name: args.projectName }),
    });
    const text = await response.text();
    if (!response.ok) {
      throw new ConvexError({
        code: "ProvisioningError",
        message: `Failed to create project backend: ${response.status}`,
        details: text,
      });
    }
    let data: {
      deploymentUrl: string;
      deploymentName: string;
      adminKey: string;
    };
    try {
      data = JSON.parse(text);
    } catch {
      throw new ConvexError({
        code: "ProvisioningError",
        message: "Provisioner returned an invalid response",
        details: text,
      });
    }
    return {
      projectSlug: args.projectSlug,
      deploymentUrl: data.deploymentUrl,
      deploymentName: data.deploymentName,
      projectDeployKey: data.adminKey,
      warningMessage: undefined as string | undefined,
    };
  },
});

const LOCAL_PROVISION_WAIT_MS = 90_000;

export const startProvisionLocalProject = mutation({
  args: {
    sessionId: v.id("sessions"),
    chatId: v.string(),
  },
  handler: async (ctx, args) => {
    await startProvisionLocalProjectHelper(ctx, args);
  },
});

export async function startProvisionLocalProjectHelper(
  ctx: MutationCtx,
  args: {
    sessionId: Id<"sessions">;
    chatId: string;
  },
): Promise<void> {
  if (!localProvisioningEnabled()) {
    throw new ConvexError({
      code: "ProvisioningError",
      message: "Local provisioning is not configured (CHEF_PROVISION_URL unset)",
    });
  }
  const chat = await getChatByIdOrUrlIdEnsuringAccess(ctx, { id: args.chatId, sessionId: args.sessionId });
  if (!chat) {
    throw new ConvexError({ code: "NotAuthorized", message: "Chat not found" });
  }
  const session = await ctx.db.get("sessions", args.sessionId);
  if (!session || session.memberId === undefined) {
    throw new ConvexError({ code: "NotAuthorized", message: "Must be logged in to connect a project" });
  }

  await ctx.scheduler.runAfter(0, internal.convexProjects.connectLocalProjectForChat, {
    sessionId: args.sessionId,
    chatId: args.chatId,
  });
  const jobId = await ctx.scheduler.runAfter(LOCAL_PROVISION_WAIT_MS, internal.convexProjects.checkConnection, {
    sessionId: args.sessionId,
    chatId: args.chatId,
  });
  await ctx.db.patch("chats", chat._id, {
    convexProject: { kind: "connecting", checkConnectionJobId: jobId },
  });
}

export const connectLocalProjectForChat = internalAction({
  args: {
    sessionId: v.id("sessions"),
    chatId: v.string(),
  },
  handler: async (ctx, args) => {
    // Stable per-chat slug so a retry reuses the same backend container.
    const chatIdDigits = args.chatId.replace(/[^a-z0-9]/gi, "").slice(0, 16) || "proj";
    const projectSlug = `chef-${chatIdDigits}`;
    try {
      let projectName = await ctx.runQuery(internal.convexProjects.getProjectName, {
        sessionId: args.sessionId,
        chatId: args.chatId,
      });
      if (!projectName) {
        projectName = "My Project (Chef)";
      }
      const data = await ctx.runAction(internal.convexProjects.provisionLocalBackend, {
        projectSlug,
        projectName,
      });
      await ctx.runMutation(internal.convexProjects.recordProvisionedConvexProjectCredentials, {
        sessionId: args.sessionId,
        chatId: args.chatId,
        projectSlug: data.projectSlug,
        teamSlug: "local",
        projectDeployKey: data.projectDeployKey,
        deploymentUrl: data.deploymentUrl,
        deploymentName: data.deploymentName,
        warningMessage: data.warningMessage,
      });
    } catch (error) {
      const message = error instanceof ConvexError ? error.data?.message ?? error.message : "Unexpected error";
      console.error(`Error connecting local convex project: ${error instanceof Error ? error.message : error}`);
      await ctx.runMutation(internal.convexProjects.recordFailedConvexProjectConnection, {
        sessionId: args.sessionId,
        chatId: args.chatId,
        errorMessage: message,
      });
    }
  },
});

export function ensureEnvVar(name: string) {
  if (!process.env[name]) {
    throw new Error(`Environment variable ${name} is not set`);
  }
  return process.env[name];
}
