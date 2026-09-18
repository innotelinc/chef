# Atlas Chef — production container for `make chef-up` (fork workstream 3b.3).
#
# `pnpm build` (remix vite:build) runs at image build time and the result is
# served by remix-serve (`pnpm start`) at runtime, so the chef container is a
# real service rather than a dev-mode `remix vite:dev` process. The compose
# `chef` service maps 127.0.0.1:4310 -> 4310 and injects the server-side
# CHEF_OIDC_*/CONVEX_*/model-key envs at runtime.
#
# Client-side envs (VITE_*) are inlined at BUILD time by remix/vite, so the
# ones the fork needs are build args with the same defaults as the compose
# service's runtime env lines (docker-compose.yml `chef` service). The
# hosted-plane envs (VITE_PROVISION_HOST) keep their defaults until fork
# workstream 3b.2 localizes provisioning; see docs/chef-auth-fork.md.
FROM node:22-slim

# corepack supplies pnpm@9.5.0 from the packageManager field.
RUN corepack enable

WORKDIR /app

# Copy the full checkout; .dockerignore keeps node_modules/.git/.env* out.
COPY . .

# Host .env.local carries real secrets and is excluded by .dockerignore —
# the compose `chef` service injects env at runtime (docker doesn't override
# existing process env, so runtime wins). depscheck.mjs requires the file to
# merely exist, hence the empty placeholder.
RUN touch .env.local

# pnpm install (frozen first; plain fallback if the lockfile drifted).
# child-concurrency + a capped heap keep install viable on memory-constrained
# hosts (the full checkout is a large dep tree; parallel extraction OOMs).
ENV NODE_OPTIONS=--max-old-space-size=3072
RUN pnpm install --frozen-lockfile --child-concurrency=2 \
    || pnpm install --child-concurrency=2

# Client-side env inlined by `remix vite:build` (build args, see above).
ARG VITE_CONVEX_URL=http://127.0.0.1:3210
ARG VITE_PROVISION_HOST=https://api.convex.dev
ENV VITE_CONVEX_URL=$VITE_CONVEX_URL
ENV VITE_PROVISION_HOST=$VITE_PROVISION_HOST

# Production build (remix vite:build -> build/server/index.js + build/client).
# vite's build worker pool is memory-hungry; a capped heap + a single worker
# (maxWorkers/numWorkers) keeps the build viable on memory-constrained hosts.
ENV NODE_OPTIONS=--max-old-space-size=3072
# The Dockerfile sets NODE_ENV=production AFTER this step, so omit --mode so
# vite inherits the build-phase default. Build-phase NODE_ENV is unset, which
# makes vite resolve the default mode; passing --mode development here forces
# development bundles that disagree with NODE_ENV=production at runtime. Let
# vite use the same mode the real `pnpm build` target uses.
RUN pnpm exec vite build \
    || pnpm build

ENV NODE_ENV=production
ENV PORT=4310

EXPOSE 4310

# remix-serve honors $PORT; the compose service pins it to CHEF_PORT.
CMD ["pnpm", "start"]
