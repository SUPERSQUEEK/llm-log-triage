#!/usr/bin/env python3
"""
llm-log-triage — ask a locally-hosted LLM to summarize security telemetry.

Pulls events from the honeypot and the Access detection Worker, then asks a
model running on my own hardware (Ollama, no data leaves the machine) to
produce a short operator briefing.

The interesting engineering here is not "call an LLM." It is the guardrails
around the call, because an unconstrained LLM over log data fails in specific,
predictable ways:

  * It invents IP addresses that look plausible and are not in the input.
  * It rounds counts, or asserts "several" where the number is knowable.
  * It confidently narrates intent ("this is a coordinated attack") from
    evidence that supports no such claim.

So: the model never sees raw logs. It sees a PRE-AGGREGATED summary computed
in Python, where the counts are already correct. Every factual claim it can
make is therefore one that was handed to it. Afterwards, verify() re-checks
that every IP and number in the output actually appeared in the input, and
flags anything that did not.

The model is used for prose, not for arithmetic and not for retrieval.
"""

import argparse
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone

def _normalize_ollama_host(raw):
    """OLLAMA_HOST is a SERVER BIND address, not a client URL.

    Anyone who has exposed Ollama to containers has it set to "0.0.0.0:11434".
    That is a valid bind address and a meaningless dial target: 0.0.0.0 means
    "every interface I own", so connecting to it fails. Naively reusing the
    variable as a base URL is a bug this script hit on the machine it was
    written on, which is exactly why it is handled here.
    """
    if not raw:
        return "http://127.0.0.1:11434"
    host = raw.strip()
    if "://" not in host:
        host = "http://" + host
    # Rewrite wildcard binds to a dialable loopback address.
    host = host.replace("://0.0.0.0", "://127.0.0.1").replace("://[::]", "://[::1]")
    return host.rstrip("/")


OLLAMA = _normalize_ollama_host(os.environ.get("OLLAMA_HOST"))
MODEL = os.environ.get("TRIAGE_MODEL", "qwen3.8")

SYSTEM = """You are a security operations assistant writing a short daily briefing.

Rules you must follow:
- Use ONLY the figures given to you. Never state a number that was not provided.
- Never write an IP address that does not appear in the input.
- Do not speculate about attacker identity, nationality, or motive.
- If the data is unremarkable, say so plainly in one sentence. Do not manufacture
  significance to fill space.
- Prefer "N requests from M addresses" over "a large volume of traffic".
- Maximum 200 words. No preamble, no sign-off.
"""


def fetch_json(url, timeout=20):
    try:
        req = urllib.request.Request(url, headers={"user-agent": "llm-log-triage"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        print(f"  ! could not fetch {url}: {e}", file=sys.stderr)
        return None


def summarize_honeypot(data):
    """Aggregate in Python so the numbers handed to the model are already right."""
    if not data:
        return None
    events = data.get("events", [])
    if not events:
        return {"total": 0}
    return {
        "total": len(events),
        "unique_ips": len({e.get("ip") for e in events if e.get("ip")}),
        "top_countries": Counter(e.get("country") for e in events if e.get("country")).most_common(5),
        "top_networks": Counter(
            e.get("asOrganization") for e in events if e.get("asOrganization")
        ).most_common(5),
        "top_paths": Counter(e.get("path") for e in events).most_common(8),
        "classifications": Counter(e.get("classification") for e in events).most_common(),
        "window": (events[-1].get("ts"), events[0].get("ts")),
    }


def summarize_findings(data):
    if not data:
        return None
    findings = data.get("findings", [])
    return {
        "total": len(findings),
        "by_severity": Counter(f.get("severity") for f in findings).most_common(),
        "by_rule": Counter(f.get("rule") for f in findings).most_common(),
        "summaries": [f.get("summary") for f in findings[:10]],
    }


def build_prompt(honeypot, findings):
    parts = ["Telemetry for the last collection window.\n"]

    if honeypot and honeypot.get("total"):
        parts.append("HONEYPOT (a hostname that serves nothing; all traffic is unsolicited):")
        parts.append(f"  total requests: {honeypot['total']}")
        parts.append(f"  unique source addresses: {honeypot['unique_ips']}")
        parts.append(f"  countries: {honeypot['top_countries']}")
        parts.append(f"  networks: {honeypot['top_networks']}")
        parts.append(f"  most-requested paths: {honeypot['top_paths']}")
        parts.append(f"  request classifications: {honeypot['classifications']}\n")
    else:
        parts.append("HONEYPOT: no events in window.\n")

    if findings and findings.get("total"):
        parts.append("ACCESS DETECTIONS:")
        parts.append(f"  findings: {findings['total']}")
        parts.append(f"  by severity: {findings['by_severity']}")
        parts.append(f"  by rule: {findings['by_rule']}")
        for s in findings["summaries"]:
            parts.append(f"  - {s}")
    else:
        parts.append("ACCESS DETECTIONS: no findings in window.")

    parts.append("\nWrite the briefing.")
    return "\n".join(parts)


def ask(prompt, model=MODEL, host=OLLAMA):
    body = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "system": SYSTEM,
            "stream": False,
            # Low temperature: this is a summarization task, not a creative one.
            #
            # num_predict must be generous because qwen3 is a REASONING model:
            # its chain-of-thought is emitted into a separate "thinking" field
            # but is billed against the same token budget. With num_predict=400
            # the model spent the entire allowance thinking and returned an
            # empty "response" — a silent failure that looks like a broken
            # pipeline rather than an exhausted budget.
            "options": {"temperature": 0.2, "num_predict": 1500},
        }
    ).encode()
    req = urllib.request.Request(
        f"{host}/api/generate", data=body, headers={"content-type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=600) as r:
        payload = json.loads(r.read().decode())

    answer = (payload.get("response") or "").strip()
    if not answer:
        thinking = (payload.get("thinking") or "").strip()
        reason = payload.get("done_reason", "unknown")
        raise RuntimeError(
            "model returned an empty response (done_reason=" + reason + "). "
            + ("It produced " + str(len(thinking)) + " characters of reasoning and then ran out of "
               "token budget; raise num_predict." if thinking else "No reasoning was produced either.")
        )
    return answer


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
NUM_RE = re.compile(r"\b\d[\d,]*\b")


def verify(output, prompt):
    """Re-check the model's output against the input it was given.

    This is the part that makes the tool trustworthy rather than merely
    convenient. Any IP or figure in the briefing that was not in the prompt is
    a hallucination, and it gets surfaced instead of being trusted.
    """
    problems = []

    for ip in set(IP_RE.findall(output)):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if ip not in prompt:
            problems.append(f"IP {ip} appears in the briefing but not in the source data")

    source_numbers = {n.replace(",", "") for n in NUM_RE.findall(prompt)}
    for n in set(NUM_RE.findall(output)):
        clean = n.replace(",", "")
        # Ignore small integers; they are usually ordinals or list positions.
        if len(clean) <= 1:
            continue
        if clean not in source_numbers:
            problems.append(f"figure {n} appears in the briefing but not in the source data")

    return problems


def main():
    # Windows consoles default to cp1252, which cannot encode the box-drawing
    # characters below. Reconfigure rather than downgrade the output.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    ap = argparse.ArgumentParser(description="LLM-assisted triage of self-hosted security telemetry")
    ap.add_argument("--honeypot-url", default=os.environ.get("HONEYPOT_URL", ""),
                    help="honeypot /_intel.json?token=... endpoint")
    ap.add_argument("--findings-url", default=os.environ.get("FINDINGS_URL", ""),
                    help="detections /api/findings endpoint")
    ap.add_argument("--model", default=MODEL)
    ap.add_argument("--dry-run", action="store_true", help="print the prompt, do not call the model")
    args = ap.parse_args()

    print(f"llm-log-triage · {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    print(f"model: {args.model} @ {OLLAMA}\n")

    honeypot = summarize_honeypot(fetch_json(args.honeypot_url)) if args.honeypot_url else None
    findings = summarize_findings(fetch_json(args.findings_url)) if args.findings_url else None

    if honeypot is None and findings is None:
        print("No telemetry sources reachable. Nothing to triage.", file=sys.stderr)
        return 1

    prompt = build_prompt(honeypot, findings)

    if args.dry_run:
        print(prompt)
        return 0

    try:
        output = ask(prompt, model=args.model)
    except RuntimeError as e:
        print(f"Triage failed: {e}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"Model unreachable at {OLLAMA}: {e}", file=sys.stderr)
        print("Is Ollama running? It gets shut down during gaming sessions.", file=sys.stderr)
        return 1

    print("─" * 64)
    print(output)
    print("─" * 64)

    problems = verify(output, prompt)
    if problems:
        print("\nVERIFICATION FAILED — the briefing contains unsupported claims:")
        for p in problems:
            print(f"  ! {p}")
        print("\nTreat this briefing as unreliable.")
        return 2

    print("\nVerified: every address and figure in the briefing appears in the source data.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
