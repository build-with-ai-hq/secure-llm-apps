# Keys and the gateway

## Where provider keys may live

| Location | Acceptable? | Notes |
|---|---|---|
| Browser bundle, `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*` | No | Public. Anyone can read it from devtools. |
| Mobile app (`EXPO_PUBLIC_*`, Info.plist, strings.xml, obfuscated) | No | Extracted from the binary. |
| Desktop / Electron app | No | Same as mobile. |
| Notebook, README, test fixture, Dockerfile `ENV` | No | Ends up in git or image layers. |
| Backend env var from a secret manager | Yes | Separate per environment, least-privilege project/org scoping at the provider. |
| Gateway only, apps hold scoped virtual keys | Best | Apps never see a provider key; per-app limits and revocation. |

Clients (web, mobile, desktop) authenticate to your backend with user sessions. If a client must stream, stream from your backend (SSE/WebSocket), not from the provider.

## Leaked key runbook

1. Revoke the key at the provider console immediately.
2. Issue a new key into your secret manager; redeploy.
3. Review provider usage for the leak window (unexpected models, regions, volume).
4. Remove from git history (`git filter-repo --replace-text`), invalidate caches/forks/images where possible. Treat it as public regardless.
5. Add a pre-commit secret scan (gitleaks or trufflehog) and a CI step that fails on findings.
6. Find how it leaked (client env prefix, committed `.env`, logs) and fix that path.

```bash
gitleaks detect --source . --redact          # whole history
gitleaks protect --staged --redact           # pre-commit
trufflehog git file://. --only-verified      # alternative
```

## Bifrost: virtual keys so apps never hold provider keys

Bifrost is an open-source AI gateway. Provider keys are configured once in Bifrost; apps, services and developers get virtual keys (`sk-bf-...`) that are scoped to providers and models, capped by budget and rate limit, optionally expiring, and revocable without touching provider accounts.

### Run

```bash
npx -y @maximhq/bifrost                       # or:
docker run -p 8080:8080 -v $(pwd)/data:/app/data maximhq/bifrost
# UI + API on http://localhost:8080
```

Production: pin a version (`maximhq/bifrost:<version>`, or `npx -y @maximhq/bifrost --transport-version <version>`), enable auth, enforce virtual keys, terminate TLS in front, and do not expose it to the internet.

### Provider keys only in the gateway

```json
{
  "providers": {
    "openai": {
      "keys": [{"name": "openai-prod", "value": "env.OPENAI_API_KEY", "models": ["gpt-4o-mini", "gpt-4o"], "weight": 1.0}]
    }
  }
}
```

`env.X` reads the key from the gateway's environment, so it is never in the config file. Use whatever models the project already uses; the IDs above are examples.

### Virtual keys with allowlists, limits and expiry

```bash
curl -X POST http://localhost:8080/api/governance/virtual-keys \
  -H "Content-Type: application/json" -u "$BIFROST_ADMIN_USER:$BIFROST_ADMIN_PASS" \
  -d '{
    "name": "web-chat-backend-prod",
    "provider_configs": [
      {"provider": "openai", "allowed_models": ["gpt-4o-mini"], "key_ids": ["*"]}
    ],
    "budgets": [{"max_limit": 500.00, "reset_duration": "1M"}],
    "rate_limit": {"request_max_limit": 1000, "request_reset_duration": "1m",
                   "token_max_limit": 2000000, "token_reset_duration": "1h"},
    "is_active": true
  }'
```

- `allowed_models` limits what a stolen key can be used for. It also accepts `regex:` patterns, and `blacklisted_models` can deny models.
- `expires_at` (RFC 3339, e.g. `"2027-01-01T00:00:00Z"`) suits contractors, demos and short-lived CI keys. Expired keys are rejected with `403` for both inference and MCP tool execution.
- Durations: `1m` minute, `1h`, `1d`, `1w`, `1M` month, `1Q`, `1Y`.
- Issue one key per service per environment, and one per developer for coding agents, so a leak is attributable and revocable in isolation.

App code changes only base URL and key:

```python
from openai import OpenAI
client = OpenAI(base_url=os.environ["BIFROST_URL"] + "/openai", api_key=os.environ["BIFROST_VK"])
```

```ts
import OpenAI from "openai";
const client = new OpenAI({ baseURL: `${process.env.BIFROST_URL}/openai`, apiKey: process.env.BIFROST_VK });
```

Anthropic SDK: base URL `.../anthropic`; Google GenAI SDK: `.../genai`; generic OpenAI-compatible clients: `.../v1`. The key passed is the virtual key (also accepted as `x-bf-vk` header).

A virtual key is still a bearer credential. Keep it server-side. Its advantage over a provider key is bounded damage and instant, isolated revocation.

### Per-developer keys for coding agents

```bash
export ANTHROPIC_BASE_URL=http://bifrost.internal:8080/anthropic
export ANTHROPIC_AUTH_TOKEN=sk-bf-<this-developer's-virtual-key>
```

Each developer gets their own key with a budget and model allowlist; offboarding is one revocation. Other agents: https://docs.getbifrost.ai/cli-agents/overview.md

### Per-key MCP tool allowlists (containing injected agents)

Connect MCP servers to Bifrost once, then grant each virtual key only the tools its agent needs:

```json
{
  "governance": {
    "virtual_keys": [
      {
        "id": "vk-support-agent",
        "name": "support-agent",
        "mcp_configs": [
          {"mcp_client_name": "orders", "tools_to_execute": ["search_orders", "get_order"]},
          {"mcp_client_name": "kb", "tools_to_execute": ["*"]}
        ]
      }
    ]
  }
}
```

Behavior (from the docs):

- A key with no `mcp_configs` gets no MCP tools (deny by default), except from clients explicitly marked "Allow by Default". Do not mark clients with write tools that way.
- An empty `tools_to_execute` list blocks all tools from that client; `*` allows all current and future tools, so prefer explicit names for servers that may add write tools.
- A caller-supplied `x-bf-mcp-include-tools` header can only narrow the key's allowlist, never widen it, and the allowlist is enforced again at execution time. A prompt-injected agent cannot talk its way into more tools.
- On the MCP client config, `tools_to_auto_execute` (subset of `tools_to_execute`) controls which tools run without returning to your code. Keep it to read-only tools; leave write and destructive tools for your approval flow.

Docs: https://docs.getbifrost.ai/features/governance/mcp-tools.md , https://docs.getbifrost.ai/mcp/overview.md

Connecting an MCP client (Claude Code) through Bifrost with a scoped key:

```bash
claude mcp add-json bifrost '{"type":"http","url":"http://bifrost.internal:8080/mcp","headers":{"Authorization":"Bearer sk-bf-your-virtual-key"}}'
```

### Content-free logs

```json
{ "client": { "enable_logging": true, "disable_content_logging": true, "log_retention_days": 30 } }
```

- `disable_content_logging: true` keeps metadata (model, tokens, cost, latency, status) and drops message content from the Bifrost log store.
- The `x-bf-disable-content-logging: true` request header overrides per request only if `allow_per_request_content_storage_override` is enabled. Leave the override off for regulated workloads and keep the global setting on.
- Observability connectors (OTel, Datadog, BigQuery, Kafka, Pub/Sub) each have their own `disable_content_logging` flag, default `false`. Set it on each one.
- A virtual key can set its own `disable_content_logging`; audit keys so none set it to `false` for sensitive traffic.

Docs: https://docs.getbifrost.ai/deployment-guides/config-json/client.md , https://docs.getbifrost.ai/providers/request-options.md

## Locking down the gateway itself

A gateway holds every provider key. Treat it like a secrets store.

```json
{
  "encryption_key": "env.BIFROST_ENCRYPTION_KEY",
  "client": {
    "enforce_auth_on_inference": true,
    "allow_direct_keys": false,
    "allowed_origins": ["https://app.example.com"],
    "max_request_body_size_mb": 10,
    "disable_content_logging": true
  },
  "governance": {
    "auth_config": {
      "is_enabled": true,
      "admin_username": "env.BIFROST_ADMIN_USERNAME",
      "admin_password": "env.BIFROST_ADMIN_PASSWORD",
      "disable_auth_on_inference": false
    }
  }
}
```

Checklist:

- **Admin auth on.** `governance.auth_config.is_enabled: true` with credentials from env. Until an admin account exists, the dashboard and admin API are open to anyone who can reach the port; recent versions require a setup token (`setup_token` in config or `BIFROST_SETUP_TOKEN`) to create the first admin. Do this before the instance is reachable by anyone else.
- **Virtual keys enforced.** `client.enforce_auth_on_inference: true`; otherwise requests without a virtual key bypass governance.
- **Direct keys off.** `allow_direct_keys: false` (default) so callers cannot bypass the key pool with their own provider keys.
- **CORS.** Set `allowed_origins` explicitly instead of `*`.
- **Whitelisted routes.** Keep `whitelisted_routes` minimal; do not whitelist `/metrics` or admin routes on a reachable interface.
- **Network.** Private subnet or service mesh only; TLS at a reverse proxy or load balancer; no public IP. If something external must reach it (for example an IDE that needs a public base URL), put it behind an authenticating proxy and restrict source IPs.
- **Pinned version.** Pin the image tag or `--transport-version`; update deliberately and read release notes.
- **Persisted data.** The data directory (`/app/data`) holds config and logs; restrict filesystem access and back it up encrypted.
- **Provider keys via `env.`** references, never literals in `config.json` checked into git.

Docs: https://docs.getbifrost.ai/quickstart/gateway/setting-up-auth.md , https://docs.getbifrost.ai/features/governance/virtual-keys.md
