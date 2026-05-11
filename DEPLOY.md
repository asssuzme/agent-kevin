# Agent Kevin — Deployment Guide

Pick a tier based on how the tool will be used:

| Use case | Tier | Effort | Cost |
|---|---|---|---|
| Just me, occasional use | **Local + ngrok/Tailscale** | 5 min | Free |
| Small team, always-on | **Railway** ⭐ recommended | 15 min | ~$5-10/mo |
| Bigger team or stricter access control | **Railway + Cloudflare Access** | 30 min | ~$5-10/mo |
| Want full control | **Fly.io / self-host VPS** | 30-60 min | $2-10/mo |

---

## Tier 1 — Local + Tailscale (or ngrok)

Best when only you need it, occasionally. Keep the server running on your laptop; expose it via a private network or a public tunnel.

**Tailscale (private, recommended for team use)**:
1. Install Tailscale on your Mac (`brew install --cask tailscale`), log in
2. Run Agent Kevin locally: `npm start`
3. Have teammates install Tailscale and join your Tailnet
4. They visit `http://<your-mac-hostname>:3000` from any device on the Tailnet — only Tailscale-authed machines see it
5. Zero exposure to the public internet

**ngrok (public temporary URL, fine for quick demos)**:
1. `brew install ngrok`, run `ngrok config add-authtoken <token>` (free signup)
2. Start Kevin: `npm start`
3. In another terminal: `ngrok http 3000`
4. Share the `https://<random>.ngrok-free.app` URL
5. **Set basic auth in `.env` first**: `ACCESS_USER=team` and `ACCESS_PASSWORD=...` — anyone with the URL can otherwise spend your OpenAI credit
6. URL changes every restart unless you have a paid ngrok plan

---

## Tier 2 — Railway (recommended for a team) ⭐

Railway runs Node apps natively, keeps SSE connections alive, sets PORT automatically, and has straightforward env var management. ~$5/mo base + usage.

**Prerequisites**:
- A GitHub account (push the repo)
- A Railway account (sign in with GitHub at https://railway.app)

**Steps**:

1. **Push to GitHub** (private repo — your OpenAI key is in `.env` but that's gitignored; double-check before pushing):
   ```bash
   cd /Users/ashutoshlath/vibehack
   git init
   git add .
   git status                 # verify .env is NOT in the list
   git commit -m "Agent Kevin v2.1"
   gh repo create agent-kevin --private --source=. --push
   ```

2. **Deploy to Railway**:
   - Go to railway.app → "New Project" → "Deploy from GitHub repo"
   - Pick `agent-kevin`
   - Railway autodetects Node, runs `npm install` + `npm start`

3. **Set env vars** in the Railway service settings → Variables tab:
   ```
   OPENAI_API_KEY=sk-proj-...
   OPENAI_BASE_URL=https://api.openai.com/v1
   MODEL_RECON=gpt-5.4
   MODEL_SPECIALIST=o3
   MODEL_MISCONFIG=gpt-5.4
   MODEL_AGGREGATOR=gpt-5.4
   REASONING_EFFORT_RECON=medium
   REASONING_EFFORT_SPECIALIST=high
   REASONING_EFFORT_MISCONFIG=low
   REASONING_EFFORT_REFLECTION=high
   REASONING_EFFORT_AGGREGATOR=low
   MAX_AGENT_ITERATIONS=999
   HTTP_TIMEOUT_MS=15000
   SCAN_USER_AGENT=AgentKevin/0.2 (internal-audit)
   ACCESS_USER=team
   ACCESS_PASSWORD=<a-strong-password-here>
   ```
   (Don't set `PORT` — Railway injects it automatically.)

4. **Generate a public domain** — Settings → Networking → "Generate Domain". You get `agent-kevin-production-xxxx.up.railway.app`. Share with the team.

5. **Optional custom domain**: Settings → Networking → Custom Domain. Add a CNAME on your registrar. Free SSL.

**Updates**: every `git push` triggers an auto-redeploy.

**Cost guard**: Railway has a "Usage Limit" setting per project — set it to $20/mo so you don't get surprise bills.

---

## Tier 3 — Railway + Cloudflare Access (SSO for teams)

When you outgrow basic auth (>3 users, want audit logs, want Google/email SSO).

After the Railway deploy is live with a custom domain:

1. Add the domain to **Cloudflare** (free plan is fine)
2. **Cloudflare Zero Trust** → Access → Applications → Add Application
3. Pick "Self-hosted", give it the Agent Kevin domain
4. Add a policy: "Emails ending in @yourcompany.com"
5. Save. Now everyone hits Cloudflare's SSO login before reaching Agent Kevin
6. Remove `ACCESS_USER` / `ACCESS_PASSWORD` from Railway env vars — Cloudflare Access is the gate now

Free for under 50 users. Audit trail of every visit. Revoke per-user instantly.

---

## Tier 4 — Fly.io (alternative)

Fly has a generous free allowance and great SSE support.

```bash
brew install flyctl
cd /Users/ashutoshlath/vibehack
fly launch --no-deploy        # creates fly.toml, pick name "agent-kevin"
fly secrets set OPENAI_API_KEY=sk-proj-... MODEL_SPECIALIST=o3 ACCESS_USER=team ACCESS_PASSWORD=...
fly deploy
```

Your app is at `https://agent-kevin.fly.dev`. Same basic-auth pattern works.

---

## Tier 5 — Self-host on a VPS

Cheapest, most flexible. Hetzner $4/mo box, DigitalOcean droplet, etc.

Standard recipe: SSH in → install Node 20 → `git clone` → `npm install` → set `.env` → run under `systemd` or `pm2` → put `nginx` or `caddy` in front for TLS + basic auth or OAuth2 proxy.

If you go this route, ping me and I'll write the systemd unit + Caddyfile.

---

## Pre-deploy checklist

- [ ] `.env` is in `.gitignore` (it is — verify with `git status` doesn't show it)
- [ ] `npm run doctor` passes locally
- [ ] `npm start` runs cleanly locally
- [ ] You've decided where you want it deployed (Railway is the default recommendation)
- [ ] You've set a `ACCESS_PASSWORD` you can share with the team (a password manager entry, not a chat message)
- [ ] You've added a usage cap on the OpenAI key (https://platform.openai.com/account/limits) so a runaway scan can't drain your account

## Post-deploy verification

After deploying:

1. Visit `https://<your-deploy-url>/healthz` — should return `{"ok":true,"service":"agent-kevin","version":"2.1"}`
2. Open the root URL, get prompted for basic-auth login (if you enabled it)
3. Run a scan against `https://testphp.vulnweb.com/` — should find a critical SQLi within a few minutes
4. Confirm cost meter updates in real time

If anything fails, check the platform's deploy logs first (Railway dashboard → Deployments → View Logs).
