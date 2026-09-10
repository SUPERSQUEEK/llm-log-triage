# LLM Log Triage

Asks a locally-hosted LLM to write a short operator briefing over security telemetry from my own infrastructure. Nothing leaves the machine — the model runs on my GPU via Ollama.

The interesting part is not calling an LLM. It is the guardrails around the call, and an honest account of where they still fail.

---

## The problem with "AI for log analysis"

Point a language model at raw logs and it will fail in three specific, repeatable ways:

1. **It invents IP addresses** that look plausible and appear nowhere in the input.
2. **It rounds counts** — "several hundred requests" where the number is exactly knowable.
3. **It narrates intent** — "a coordinated attack from Eastern Europe" — from evidence supporting no such claim.

All three produce output that *reads* authoritative. That is what makes it dangerous rather than merely useless.

## What this does instead

**The model never sees raw logs.** Python aggregates first — counts, top-N by country, by network, by path, by classification — and the model receives only that pre-computed summary. Every factual claim available to it is therefore one that was handed to it, already correct.

**The model is used for prose, not arithmetic and not retrieval.**

**Output is verified against input.** After generation, `verify()` extracts every IP address and every figure from the briefing and confirms each appears in the source data. Anything that doesn't is reported as an unsupported claim and the exit code goes non-zero.

```console
$ python triage.py --honeypot-url ... --findings-url ...
llm-log-triage · 2026-09-10T01:55:25+00:00
model: qwen3.8:latest @ http://127.0.0.1:11434

────────────────────────────────────────────────────────────────
Honeypot received 18 requests from 7 unique source addresses in the
collection window. Origins: US (15), NL (3). Networks: Charter
Communications Inc (7), DigitalOcean, LLC (4), ReliableSite.Net LLC (3),
UAB code200 (3), DEDIK SERVICES LIMITED (1).
...
Volume and composition are unremarkable for a honeypot endpoint.
────────────────────────────────────────────────────────────────

Verified: every address and figure in the briefing appears in the source data.
```

## Where it still fails — a real example

That run passed verification. It was still wrong.

The model wrote: *"the remaining 9 were distributed one each across /sitemap.xml, /robots.txt, /favicon.ico, /\_intel, /login, /nonsense, and /.env."*

That is **seven** paths, described as **nine** hits. The arithmetic doesn't close, and `verify()` passed it anyway — because `9` genuinely appears in the source data, just attached to a different fact.

This is the honest limit of the approach:

> **Token-level verification catches fabricated *values*. It cannot catch fabricated *relationships* between values that are individually real.**

Catching that class of error needs the checker to reconstruct the model's claims structurally — parse "N distributed across list L" and assert `N == len(L)` — which is most of the way toward not needing the model at all. That tension is the actual finding of this project.

**Conclusion I'd defend in an interview:** an LLM is a reasonable *presentation* layer over telemetry that has already been correctly aggregated, and an unacceptable *analysis* layer. It should never be the thing that decides whether something is worth waking someone up for.

## Two bugs worth keeping

Both were hit on the machine this was written on, and both are handled in code rather than in a wiki page:

**`OLLAMA_HOST` is a server bind address, not a client URL.** Anyone who has exposed Ollama to Docker containers has it set to `0.0.0.0:11434`. That is a valid bind address and a meaningless dial target — `0.0.0.0` means "every interface I own." Naively reusing the variable as a base URL fails with `unknown url type`. `_normalize_ollama_host()` adds the missing scheme and rewrites wildcard binds to loopback.

**Reasoning models spend your token budget thinking.** `qwen3` emits chain-of-thought into a separate `thinking` field that is billed against the same `num_predict` allowance. At `num_predict: 400` the model spent the entire budget reasoning and returned an **empty** `response` — a silent failure that looks like a broken pipeline. The budget is now 1500, and an empty response raises with the reason and the size of the reasoning it produced instead of printing nothing.

## Usage

```bash
python triage.py \
  --honeypot-url "https://vpn.example.com/_intel.json?token=..." \
  --findings-url "https://access-log-detections.example.workers.dev/api/findings"

python triage.py --dry-run ...     # print the prompt, don't call the model
```

| Env var | Default | Meaning |
|---|---|---|
| `OLLAMA_HOST` | `http://127.0.0.1:11434` | Normalized; wildcard binds rewritten to loopback |
| `TRIAGE_MODEL` | `qwen3.8` | Any Ollama model |
| `HONEYPOT_URL` / `FINDINGS_URL` | — | Defaults for the flags |

Exit codes: `0` verified · `1` unreachable source or model · `2` **briefing contains unsupported claims**.

## Requires

Python 3.9+ (standard library only) · [Ollama](https://ollama.com) with any chat model

Companion to [honeypot-edge](https://github.com/SUPERSQUEEK/honeypot-edge) and [access-log-detections](https://github.com/SUPERSQUEEK/access-log-detections).

## License

MIT
