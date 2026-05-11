# Agent Kevin

Multi-agent security audit tool. Paste a URL, eleven OpenAI agents audit it in parallel against OWASP ASVS/WSTG, then return a structured report.

Built for pre-ship hardening of your own apps. Live agent traces, live cost meter, live target graph (stack + endpoints + secrets extracted from JS bundles), markdown report.

## Quick start (local)

```bash
cd agent-kevin
npm install
cp .env.example .env       # then fill in OPENAI_API_KEY
npm start
```

Open `http://localhost:3000`, paste a URL, hit Scan.

Pre-flight prompt check (validates filter doesn't trip — costs ~$0.12):

```bash
npm run doctor
```

## What runs

1. **Recon** — extracts JS bundles, fingerprints the stack, populates a shared target graph
2. **5 generic specialists in parallel** — Injection, Auth, XSS, SSRF, Misconfig
3. **Stack-aware playbooks** that fire only when relevant — Supabase, Clerk, GraphQL, Next.js
4. **Reflection pass** — chases coverage gaps left by earlier agents
5. **Aggregator** — dedupes + CVSS-scores + renders Markdown

Models (in `.env`):
- `MODEL_RECON=gpt-5.4`
- `MODEL_SPECIALIST=o3` (reasoning model, passes OpenAI's content filter; gpt-5.5 family does not)
- `MODEL_MISCONFIG=gpt-5.4`
- `MODEL_AGGREGATOR=gpt-5.4`

## Deployment

See [DEPLOY.md](./DEPLOY.md) for step-by-step instructions covering:
- **Railway** (recommended — Node-friendly, supports SSE, ~$5-10/mo for an internal-team tool)
- **Fly.io** (alternative — generous free tier)
- **Local + Tailscale or ngrok** (simplest — share your laptop instance with the team)

All paths include the optional basic-auth gate (`ACCESS_USER` + `ACCESS_PASSWORD` env vars) so anyone with the URL can't just walk in.

## Safety knobs (in `.env`)

- `MAX_AGENT_ITERATIONS` — hard cap per agent (default 999 = effectively no cap)
- `MAX_CONCURRENT_SCANS` — queue beyond this (default 3)
- `HTTP_TIMEOUT_MS` — per-request timeout (default 15s)
- `SOFT_COST_WARN_USD` — UI banner past this; doesn't kill the scan

Agents are instructed never to run destructive operations (no DROP/DELETE without WHERE, no DoS traffic). They stop at proof.

## ⚠️ Authorization

Agent Kevin is for auditing **applications you own or have written authorization to test**. There is no domain allowlist — your team is on the honor system. Scanning a stranger's site is illegal in most jurisdictions.

## Test target

`https://testphp.vulnweb.com/` — Acunetix's public legal pentest practice site, known SQLi on `artists.php?artist=1`.

## Architecture

Design doc: `~/.claude/plans/tender-leaping-wirth.md`
