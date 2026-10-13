# Optional AI classification (self-hosted model)

Rules and fingerprints catch structured data (cards, IDs, keys) and known files. Some confidential documents have no fixed pattern - a draft contract, unreleased financials, an M&A memo. OpenDLP can optionally ask a **model your organisation runs itself** to classify documents that no rule matched.

**Off by default.** Document text is sent only to the endpoint you configure. Do not point it at a third-party AI service unless your policy allows sending documents there - that would itself be a data leak.

## Setup

1. Run [Ollama](https://ollama.com) on a server inside your network and pull a small model, e.g. `ollama pull llama3.2:3b`.
2. In the policy (`policies/default-policy.json` or `PUT /api/v1/admin/policy`):
   ```json
   "ai": { "enabled": true, "endpoint": "http://ai.internal:11434", "model": "llama3.2:3b", "maxChars": 4000, "action": "alert" }
   ```
   Agents pick it up on their next policy poll.

## What happens

- Only files in monitored folders, of supported types (text, Office, zip), where **no rule matched**, are classified.
- Only the first `maxChars` characters are sent. At most 20 requests per minute per agent; failures are ignored.
- The model answers `public`, `internal` or `confidential`. `confidential` raises an `AI_CLASSIFIED` event (`action`: `alert` or `log`) with the model's short reason.
- The prompt tells the model to ignore instructions inside the document, but a classifier can be fooled - treat AI results as a hint for review, not as proof.
