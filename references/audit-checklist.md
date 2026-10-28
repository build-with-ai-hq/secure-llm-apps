# LLM app security audit checklist

Use this for a full review. Run the greps, read every hit in context, then fill in the checklist. Report findings as: location, risk, exploit sketch, fix, verification step.

## Grep list

Define a helper once (works in bash and zsh):

```bash
g() { grep -rnE --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=build \
  --exclude-dir=.next --exclude-dir=.venv --exclude-dir=venv "$1" .; }
```

### Keys and secrets

```bash
g "sk-(proj-)?[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|gsk_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{30,}"
g "(NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP|NUXT_PUBLIC|PUBLIC)_[A-Z_]*(KEY|TOKEN|SECRET)"
g "dangerouslyAllowBrowser"
g "api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9_-]{16,}"
git ls-files | grep -E "(^|/)\.env($|\.)" | grep -v "\.example$"     # committed env files
gitleaks detect --source . --redact                                  # history
# Built artifacts (run after a production build)
grep -rlE "sk-|sk-ant-|AIza" dist/ build/ .next/static/ 2>/dev/null
```

### Prompt construction and untrusted content

```bash
g "system_prompt|SYSTEM_PROMPT|role.{0,4}system"        # inspect for secrets / authz logic
g "similarity_search|as_retriever|vector_store|\.query\(|retrieve\("
g "requests\.get|httpx\.|fetch\(|axios\.|urlopen|playwright|puppeteer|BeautifulSoup"
g "read_email|gmail|imap|slack|jira|github.*issues|zendesk"
```

For each retrieval/fetch hit: is the content delimited, does it taint the session, can it reach a tool call without approval?

### Tools and agents

```bash
g "@tool|StructuredTool|tools\s*=\s*\[|tool_choice|function_call|functions\s*="
g "mcpServers|mcp_servers|MCPClient|tools_to_execute|tools_to_auto_execute"
g "def (delete|remove|drop|send|transfer|refund|pay|deploy|execute|run)_"
g "max_iterations|maxSteps|max_steps|recursion_limit|max_turns"
```

For each tool: risk class (read/write/destructive), who authorizes, are identity args injected from session, is there an approval step, is there a step cap?

### Output sinks

```bash
g "dangerouslySetInnerHTML|innerHTML\s*=|outerHTML|v-html|\{\{\{|\|\s*safe\b|mark_safe\(|Markup\("
g "marked\(|markdown-it|react-markdown|rehype-raw|allowDangerousHtml|sanitize\s*:\s*false"
g "eval\(|exec\(|new Function\(|vm\.run|compile\("
g "shell=True|os\.system\(|os\.popen\(|subprocess\.(call|run|Popen)\(.*f['\"]|child_process|execSync\(|spawn\(.*shell:\s*true"
g "f\"(SELECT|INSERT|UPDATE|DELETE)|f'(SELECT|INSERT|UPDATE|DELETE)|\.format\(.*(SELECT|INSERT|UPDATE|DELETE)|\`(SELECT|INSERT|UPDATE|DELETE)[^\`]*\\$\{"
g "raw\(|execute_raw|queryRawUnsafe|text\(f['\"]|sequelize\.query\("
g "json\.loads\(.*(content|completion|output)|JSON\.parse\(.*(content|completion|output)"   # validated after parse?
```

### Consumption

```bash
g "max_tokens|max_output_tokens|maxTokens|max_completion_tokens"
g "rate.?limit|ratelimit|slowapi|express-rate-limit|limiter"
g "timeout\s*[:=]"
```

Every LLM endpoint: authenticated? per-user limit? input length cap? output cap? timeout?

### Data and logging

```bash
g "(log(ger)?|console|print)\.?(info|debug|log|warn|error)?\(.*(prompt|messages|completion|choices|content)"
g "presidio|redact|anonymi[sz]e|scrub|mask"
g "sentry|datadog|opentelemetry|otel|tracing|telemetry|callbacks?="   # what do these capture?
g "Authorization|x-api-key" | grep -iE "log|print|console"
```

### Gateway / MCP server deployment

```bash
g "maximhq/bifrost(:latest)?\b|@maximhq/bifrost"            # pinned version?
g "\"is_enabled\"|enforce_auth_on_inference|allow_direct_keys|allowed_origins|disable_content_logging"
g "0\.0\.0\.0:8080|ports:\s*-\s*\"?8080"                      # exposed publicly?
```

## Checklist (mapped to the OWASP Top 10 for LLM Applications, 2026 edition)

Numbering follows the 2026 edition (https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/). Excessive agency, unbounded consumption and misinformation moved up; system prompt leakage is now hidden context exposure, which treats anything placed in the model's context as readable by an attacker.

### LLM01:2026 Prompt injection
- [ ] All untrusted content (RAG, files, email, web, tool results) is delimited and marked as data.
- [ ] Session is tainted when untrusted content enters; write/destructive tools then need approval.
- [ ] High-risk read-then-act flows use the quarantine pattern or schema-only handoff.
- [ ] Injection payloads from `prompt-injection.md` run as CI regression tests.

### LLM02:2026 Sensitive information disclosure
- [ ] Only needed fields are sent; PII redacted or pseudonymized locally (Presidio) before the call.
- [ ] Pasted secrets are detected and masked; user told to rotate.
- [ ] Retrieval filtered by tenant and permissions in the query.
- [ ] Provider retention/training settings confirmed for the account.

### LLM03:2026 Excessive agency
- [ ] Each agent has the minimal tool set; read and write tools separated.
- [ ] Identity and tenant arguments injected from the session, not the model.
- [ ] Destructive tools require human approval showing exact arguments.
- [ ] Step, tool-call and time limits on agent loops.
- [ ] MCP tools allowlisted per agent key (e.g. Bifrost `mcp_configs` / `tools_to_execute`); auto-execution limited to read-only tools.

### LLM04:2026 Supply chain
- [ ] MCP servers, model files, and SDKs pinned and from trusted sources; tool descriptions reviewed.
- [ ] Gateway image/version pinned.

### LLM05:2026 Data and model poisoning
- [ ] Who can write to the RAG corpus or fine-tuning data is controlled and audited.
- [ ] User-submitted content is not indexed into shared corpora without review.

### LLM06:2026 Unbounded consumption
- [ ] All LLM endpoints authenticated.
- [ ] Per-user and per-tenant request and token limits, plus a global ceiling.
- [ ] Input size, `max_tokens`, retrieved chunk count and timeouts capped.
- [ ] Budgets with alerts (e.g. per-virtual-key `budgets` and `rate_limit` in Bifrost).

### LLM07:2026 Misinformation
- [ ] High-stakes outputs cite sources or are reviewed by a human; the UI says the answer is generated.

### LLM08:2026 Hidden context exposure (2025: System prompt leakage)
- [ ] System prompt contains no secrets, credentials, internal URLs or authorization rules.
- [ ] Canary string monitored in outputs.
- [ ] Nothing in the context window (system prompt, retrieved documents, tool results, memory) is something the user is not allowed to see.

### LLM09:2026 Vector and embedding weaknesses
- [ ] Per-tenant isolation in the vector store enforced in code.
- [ ] Caches (exact and semantic) keyed by tenant/user.

### LLM10:2026 Improper output handling
- [ ] Model output parsed into pydantic/zod schemas with enums, patterns and bounds; invalid output fails closed.
- [ ] No model output in SQL strings, shell strings, `eval`, or raw HTML.
- [ ] Markdown rendered without raw HTML, sanitized, link/image hosts allowlisted.
- [ ] URLs from the model are host-allowlisted and SSRF-protected.

### Keys and infrastructure
- [ ] No provider key in any client bundle, mobile binary, repo or image layer.
- [ ] Secret scanning in pre-commit and CI.
- [ ] Apps hold scoped, revocable keys (gateway virtual keys) rather than provider keys.
- [ ] Gateway: admin auth on, virtual keys enforced on inference, direct keys off, explicit CORS origins, private network, TLS, pinned version.

### Logging
- [ ] Default logs contain metadata only; content logging off in app, gateway and every exporter.
- [ ] Auth headers never logged; error responses do not echo prompts.
- [ ] Any retained content is redacted, access-restricted, and has a retention period.

## Report template

```
## Finding: <short title>
Severity: critical | high | medium | low
Location: path/to/file.py:123
Category: LLM0X <name>
Risk: what an attacker can do, in one or two sentences.
Exploit sketch: the input or content that triggers it.
Fix: concrete code/config change.
Verify: the test or command that proves it is fixed.
```
