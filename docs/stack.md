# Chef in the Innotel Platform Stack

**Role: CodeOps** — An AI agent that builds the app you describe, in its own workspace.

Part of the [Innotel Platform Stack](https://github.com/innotelinc/innotel-platform-stack).
The canonical definition of the stack, its shared layers and their owners lives
there; this file records only what Chef does inside it.

## Boundaries

### Owns

- the agent loop and workspace
- the project scaffolding and run path
- the deployment hand-off

### Consumes

- an OpenAI-compatible model gateway
- Convex (optional backend)
- Cerulean Vault (deployment secrets)

### Does not own

- the model providers
- the deployment platform
- identity (Cerulean)

## Service map

| Component | Technology | Job |
| --- | --- | --- |
| Chef | Node.js / TypeScript | An AI agent that builds the app you describe, in its own workspace. |
| Identity | Cerulean Authentik | Sign-in and role claims, where the repo has a UI |
| Secrets | Cerulean Vault (KV v2) | Production credentials, referenced as `vault://` |
| Trust | Cerulean | DNS, TLS and the public hostname |
| Edge | NPM Edge | The public route in front of the service |

## In the ecosystem

- **Identity** comes from Cerulean Authentik; this repo holds no second account
  table and no password of its own.
- **Secrets** come from Cerulean Vault. `.env` is local only and is never
  committed; a `vault://` reference is resolved by the deployment.
- **Trust and edge** are Cerulean's and NPM Edge's. This repo does not write DNS
  records or call the NPM API directly.
- **Storage, billing and telephony** belong to ONYX, Magnate and Zeus
  respectively; Chef consumes them only where the boundaries above say
  so.

## See also

- [README](../README.md)
- [Innotel Platform Stack](https://github.com/innotelinc/innotel-platform-stack)
