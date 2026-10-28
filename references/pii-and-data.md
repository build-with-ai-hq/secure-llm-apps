# PII, secrets and data handling

Every prompt is a data transfer to a third party. Decide what may leave, strip the rest locally, and keep content out of places it does not need to be (logs, traces, analytics).

## Decide first

| Question | Typical answer |
|---|---|
| Which fields does the task actually need? | Usually far fewer than the record you have. Send the ticket text, not the customer object. |
| Is the data regulated (health, payment, children, government ID)? | If yes: contract terms (DPA/BAA), region, retention and training settings must be confirmed before any call. |
| Does the answer need to reference the entity? | If yes: reversible pseudonymization. If no: irreversible redaction. |
| Who can read stored prompts/completions? | Should be a small, audited group with short retention. |

## Local redaction with Presidio

[Presidio](https://github.com/data-privacy-stack/presidio) runs on your infrastructure (library or containers), so detection happens before data leaves. It is pattern + NER based: tune entities, add custom recognizers for your own IDs, and measure recall on a sample of real data. It will miss some PII; combine with field minimization.

### Python

```bash
pip install presidio-analyzer presidio-anonymizer
python -m spacy download en_core_web_lg
```

Irreversible redaction:

```python
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

analyzer = AnalyzerEngine()
analyzer.registry.add_recognizer(PatternRecognizer(
    supported_entity="CUSTOMER_ID",
    patterns=[Pattern("customer_id", r"\bcus_[A-Za-z0-9]{14}\b", 0.9)],
))
anonymizer = AnonymizerEngine()
ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN",
            "IBAN_CODE", "IP_ADDRESS", "LOCATION", "CUSTOMER_ID"]

def redact(text: str) -> str:
    res = analyzer.analyze(text=text, entities=ENTITIES, language="en", score_threshold=0.4)
    return anonymizer.anonymize(text=text, analyzer_results=res,
        operators={"DEFAULT": OperatorConfig("replace", {"new_value": "<REDACTED>"})}).text
```

Reversible pseudonymization (the model sees `<PERSON_1>`, your code restores the real value in the answer; the mapping never leaves your process):

```python
def pseudonymize(text: str) -> tuple[str, dict[str, str]]:
    results = analyzer.analyze(text=text, entities=ENTITIES, language="en", score_threshold=0.4)
    results = sorted(results, key=lambda r: r.start, reverse=True)   # replace right-to-left
    mapping, seen, counters = {}, {}, {}
    for r in results:
        original = text[r.start:r.end]
        if original not in seen:
            counters[r.entity_type] = counters.get(r.entity_type, 0) + 1
            seen[original] = f"<{r.entity_type}_{counters[r.entity_type]}>"
            mapping[seen[original]] = original
        text = text[:r.start] + seen[original] + text[r.end:]
    return text, mapping

def restore(text: str, mapping: dict[str, str]) -> str:
    for token, original in mapping.items():
        text = text.replace(token, original)
    return text

safe_prompt, mapping = pseudonymize(user_text)
answer = restore(call_llm(safe_prompt), mapping)
```

Overlapping detections: Presidio can return overlapping spans. Resolve overlaps (keep highest score) before replacing if your entity list makes overlaps likely.

### TypeScript (Presidio REST containers)

Presidio ships analyzer and anonymizer as HTTP services. Run them inside your network:

```bash
docker run -d -p 5002:3000 mcr.microsoft.com/presidio-analyzer:latest
docker run -d -p 5001:3000 mcr.microsoft.com/presidio-anonymizer:latest
```

Pin image tags in production.

```ts
const ANALYZER = process.env.PRESIDIO_ANALYZER_URL ?? "http://localhost:5002";
const ANONYMIZER = process.env.PRESIDIO_ANONYMIZER_URL ?? "http://localhost:5001";

export async function redact(text: string): Promise<string> {
  const analyzerResults = await fetch(`${ANALYZER}/analyze`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text, language: "en", score_threshold: 0.4 }),
  }).then((r) => r.json());
  const out = await fetch(`${ANONYMIZER}/anonymize`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      text, analyzer_results: analyzerResults,
      anonymizers: { DEFAULT: { type: "replace", new_value: "<REDACTED>" } },
    }),
  }).then((r) => r.json());
  return out.text;
}
```

For reversible pseudonymization in TS, use the `/analyze` spans and replace right-to-left in your own code, as in the Python example.

Fail closed: if the redaction service is down, do not send the raw text. Return an error or queue.

## Secrets pasted into prompts

Users paste API keys, `.env` files, connection strings and private keys into chats and coding agents. Scan before sending:

```python
import re
SECRET_PATTERNS = {
    "openai_key": r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}",
    "anthropic_key": r"sk-ant-[A-Za-z0-9_-]{20,}",
    "aws_access_key": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
    "github_token": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
    "google_api_key": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "slack_token": r"\bxox[abpr]-[A-Za-z0-9-]{10,}\b",
    "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----",
    "conn_string": r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^\s:@]+:[^\s@]+@",
    "jwt": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
}
COMPILED = {k: re.compile(v) for k, v in SECRET_PATTERNS.items()}

def mask_secrets(text: str) -> tuple[str, list[str]]:
    found = []
    for name, rx in COMPILED.items():
        if rx.search(text):
            found.append(name)
            text = rx.sub(f"<{name.upper()}_REMOVED>", text)
    return text, found
```

```ts
const SECRET_PATTERNS: Record<string, RegExp> = {
  openai_key: /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/g,
  anthropic_key: /sk-ant-[A-Za-z0-9_-]{20,}/g,
  aws_access_key: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
  github_token: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
  private_key: /-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/g,
  conn_string: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s:@]+:[^\s@]+@/g,
};
export function maskSecrets(text: string) {
  const found: string[] = [];
  for (const [name, rx] of Object.entries(SECRET_PATTERNS)) {
    if (rx.test(text)) { found.push(name); rx.lastIndex = 0; text = text.replace(rx, `<${name.toUpperCase()}_REMOVED>`); }
  }
  return { text, found };
}
```

When a secret is found, mask it and tell the user to rotate it; it has likely been pasted elsewhere too. For broader coverage, reuse gitleaks rule definitions.

## Retrieval and multi-tenant data

- Filter retrieval by tenant and by the user's document permissions in the vector store query itself, not after the model sees results.
- Do not mix tenants in one index without a mandatory metadata filter enforced in code.
- Strip PII from documents at ingestion when the use case allows it; it is cheaper than redacting every query.
- Conversation memory and caches (including semantic caches) must be keyed by tenant/user so one user's content never answers another's prompt.

## Logging hygiene

Default: log metadata, not content.

```python
import hashlib, logging
log = logging.getLogger("llm")
def log_call(req_id, user_id, model, usage, tools, status):
    log.info("llm_call", extra={
        "req_id": req_id, "user": hashlib.sha256(user_id.encode()).hexdigest()[:16],
        "model": model, "in_tok": usage.prompt_tokens, "out_tok": usage.completion_tokens,
        "tools": tools, "status": status,
    })
```

```ts
logger.info({ reqId, user: sha256(userId).slice(0, 16), model,
  inTok: usage.prompt_tokens, outTok: usage.completion_tokens, tools, status }, "llm_call");
```

- Configure HTTP client and framework loggers so request bodies and `Authorization`/`x-api-key` headers are not logged (check debug-level SDK logging, proxies, APM auto-instrumentation, error trackers capturing request payloads).
- Tracing/LLM observability tools: confirm what they capture and where it goes. Redact before export or disable content capture.
- If content is retained for evals or debugging: redact first, restrict access, set retention (days, not years), and document it.
- Error messages returned to users must not include prompts, stack traces or upstream provider errors that echo request content.

With Bifrost in front of providers, set `disable_content_logging: true` in the `client` block and on each observability connector to keep only metadata. Use the `x-bf-disable-content-logging: true` header per request only if `allow_per_request_content_storage_override` is enabled, and keep that override off for regulated traffic. See `keys-and-gateway.md`.
