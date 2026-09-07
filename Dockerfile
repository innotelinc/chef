# Atlas Chef — dev-mode container for `make chef-up`.
#
# The Chef auth fork runs `remix vite:dev` pinned to 0.0.0.0:4310
# (vite.config.ts `server` block); the compose `chef` service maps
# 127.0.0.1:4310 -> 4310 and injects the CHEF_OIDC_*/CONVEX_* envs at
# runtime. Production serve (pnpm build + remix-serve) is fork workstream
# 3b.3 and not baselined yet — see docs/chef-auth-fork.md.
FROM node:22-slim

# corepack supplies pnpm@9.5.0 from the packageManager field.
RUN corepack enable

WORKDIR /app

# Copy the full checkout; .dockerignore keeps node_modules/.git out.
COPY . .

# Host .env.local carries real secrets and is excluded by .dockerignore —
# the compose `chef` service injects env at runtime (docker doesn't override
# existing process env, so runtime wins). depscheck.mjs requires the file to
# merely exist, hence the empty placeholder.
RUN touch .env.local

# pnpm install (frozen first; plain fallback if the lockfile drifted).
RUN pnpm install --frozen-lockfile || pnpm install

EXPOSE 4310

ENV PORT=4310

CMD ["pnpm", "dev"]
