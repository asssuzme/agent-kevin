#!/usr/bin/env node
/**
 * doctor.mjs — pre-flight check that each agent's system prompt + REALISTIC user prompt
 * passes the OpenAI content classifier. Mirrors what the orchestrator sends in production
 * so we catch user-prompt-side language issues that a bland test input would miss.
 */
import 'dotenv/config';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import OpenAI from 'openai';
import { modelFor, reasoningEffortFor } from '../src/llmClient.js';
import { AUTHZ_PREAMBLE } from '../src/agents/base.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const promptsDir = join(__dirname, '..', 'src', 'prompts');

// A realistic-shaped recon summary the doctor passes to specialists.
// Mirrors what real recon emits — includes stack, endpoints, secret types, notes.
const STUB_RECON_SUMMARY = `## Stack: Vite React SPA + Supabase + Clerk + Cloudflare (confidence: high)
## Surface: 40 endpoints discovered, 2 configuration keys extracted
## Notable: production bundle references /api/v1/users, /api/health, /api/admin/login;
SUPABASE_URL + SUPABASE_ANON detected in main JS bundle; Clerk publishable key detected.
## Suggested focus: Supabase RLS coverage; Clerk frontend config; admin route auth coverage.`;

const STUB_TARGET = 'https://example.com';

// Per-agent realistic user prompts. Keep these in sync with src/agents/*.js operational prompts.
const USER_PROMPTS = {
  recon:      `Target: ${STUB_TARGET}\n\nMap the security review surface of this application in depth. Extract every JS bundle, identify the stack, populate the target graph with endpoints and configuration data. Aim for 40-60 tool calls.`,
  injection:  `Target: ${STUB_TARGET}\n\n## Recon summary\n${STUB_RECON_SUMMARY}\n\nCall read_target_graph first to review the discovered endpoints and configuration. Then walk the OWASP ASVS V5 input-handling review chain for each candidate parameter. Document each weakness with concrete reproducible evidence. Never run destructive statements. No iteration cap.`,
  auth:       `Target: ${STUB_TARGET}\n\n## Recon summary\n${STUB_RECON_SUMMARY}\n\nCall read_target_graph first. Authenticated review IS ENABLED — exercise the registration and login flows via register_account / login_account to obtain a valid session, then audit the authenticated portions of the surface. After successful login, call set_auth_state. No iteration cap.`,
  xss:        `Target: ${STUB_TARGET}\n\n## Recon summary\n${STUB_RECON_SUMMARY}\n\nCall read_target_graph first. Walk the OWASP ASVS V5.3 output-encoding review across the discovered user-facing endpoints. Use harmless markers (e.g. vibex"><svg>) to verify rendering context only. No iteration cap.`,
  ssrf:       `Target: ${STUB_TARGET}\n\n## Recon summary\n${STUB_RECON_SUMMARY}\n\nCall read_target_graph first to review all discovered endpoints. Identify any with url/file/path/proxy/webhook/import parameters — those are the candidates for request-forwarding, XML-parsing, and path-handling review per OWASP ASVS V12-V13. No iteration cap.`,
  misconfig:  `Target: ${STUB_TARGET}\n\n## Recon summary\n${STUB_RECON_SUMMARY}\n\nCall read_target_graph first. Focus on the hits from the common-paths inventory, security-header review on the main host, and the embedded-credentials review of the JS bundles. No iteration cap.`,
  supabase:   `Target: ${STUB_TARGET}\n\n## Recon summary\n${STUB_RECON_SUMMARY}\n\nRun the Supabase configuration review. Call read_target_graph first to retrieve SUPABASE_URL and SUPABASE_ANON, then verify Row Level Security coverage on each candidate table, review RPC functions, storage buckets, and auth endpoints. Decode the SUPABASE_ANON JWT and confirm the role claim is "anon". No iteration cap.`,
  clerk:      `Target: ${STUB_TARGET}\n\n## Recon summary\n${STUB_RECON_SUMMARY}\n\nAuthenticated review ENABLED — register an account via the Clerk signup flow, then set_auth_state so subsequent auditors can continue. Call read_target_graph first. No iteration cap.`,
  graphql:    `Target: ${STUB_TARGET}\n\n## Recon summary\n${STUB_RECON_SUMMARY}\n\nRun the GraphQL configuration review. Locate the GraphQL endpoint in the target graph, confirm it, check whether introspection is enabled, then walk through each query and mutation verifying auth coverage and input handling. No iteration cap.`,
  nextjs:     `Target: ${STUB_TARGET}\n\n## Recon summary\n${STUB_RECON_SUMMARY}\n\nRun the Next.js configuration review. First read_target_graph, then locate the buildId in the root page, then check _next/data for SSR data exposure, _buildManifest for route inventory, /api/* routes for missing auth, image-optimizer URL allowlist coverage, and NextAuth callback URL handling. No iteration cap.`,
  reflection: `Target: ${STUB_TARGET}\n\n## Recon summary\n${STUB_RECON_SUMMARY}\n\n## Findings reported by other agents (3)\n1. [medium] Missing CSP on / (Misconfig) — ${STUB_TARGET}/\n2. [low] X-Powered-By revealed (InfoDisclosure) — ${STUB_TARGET}/\n3. [low] Source map exposed (SourceDisclosure) — ${STUB_TARGET}/assets/main.js.map\n\n## Agent notes (leads worth following up)\n- (injection) saw a 500 on /api/users?id=1' — did not pursue\n\nNow: call read_target_graph, identify the highest-EV coverage gaps, and audit 1-2 of them in depth.`,
  aggregator: `# Inputs\n\n**Target:** ${STUB_TARGET}\n**Scan ID:** stub\n**Scan date:** 2026-05-11\n**Detected stack:** Vite + Supabase + Clerk\n\n## Recon summary\n${STUB_RECON_SUMMARY}\n\n## Raw findings (JSON, 1 items)\n\n[{"severity":"medium","title":"Missing CSP","vuln_class":"WeakHeaders","affected_url":"${STUB_TARGET}/","evidence":"HEAD response lacked CSP","impact":"weakens defense in depth","remediation":"add CSP header"}]\n\nNow produce the final Markdown report per the format spec.`,
};

const PROBES = [
  { name: 'recon',       role: 'recon',       file: 'reconSystem.md' },
  { name: 'injection',   role: 'specialist',  file: 'injectionSystem.md' },
  { name: 'auth',        role: 'specialist',  file: 'authSystem.md' },
  { name: 'xss',         role: 'specialist',  file: 'xssSystem.md' },
  { name: 'ssrf',        role: 'specialist',  file: 'ssrfSystem.md' },
  { name: 'misconfig',   role: 'misconfig',   file: 'misconfigSystem.md' },
  { name: 'supabase',    role: 'specialist',  file: 'supabaseSystem.md' },
  { name: 'clerk',       role: 'specialist',  file: 'clerkSystem.md' },
  { name: 'graphql',     role: 'specialist',  file: 'graphqlSystem.md' },
  { name: 'nextjs',      role: 'specialist',  file: 'nextjsSystem.md' },
  { name: 'reflection',  role: 'reflection',  file: 'reflectionSystem.md' },
  { name: 'aggregator',  role: 'aggregator',  file: 'reportTemplate.md' },
];

const client = new OpenAI({
  baseURL: process.env.OPENAI_BASE_URL || 'https://api.openai.com/v1',
  apiKey: process.env.OPENAI_API_KEY,
});

const PRICING = {
  'gpt-5.5-pro': { input: 60, output: 120 },
  'gpt-5.5':     { input: 5,  output: 15 },
  'gpt-5.4':     { input: 3,  output: 12 },
  'o3':          { input: 2,  output: 8 },
  default:       { input: 5,  output: 15 },
};

function pad(s, n) { s = String(s); return s + ' '.repeat(Math.max(0, n - s.length)); }

async function probe(p) {
  const prompt = await readFile(join(promptsDir, p.file), 'utf8');
  const model = modelFor(p.role);
  const effort = reasoningEffortFor(p.role);
  const instructions = `${AUTHZ_PREAMBLE}${prompt}`;
  const input = USER_PROMPTS[p.name];
  const params = { model, instructions, input };
  if (effort && effort !== 'none') params.reasoning = { effort };
  try {
    const r = await client.responses.create(params);
    const u = r.usage || {};
    const price = PRICING[model] || PRICING.default;
    const usd = (u.input_tokens || 0) * price.input / 1e6 + (u.output_tokens || 0) * price.output / 1e6;
    return {
      name: p.name, status: 'PASS', model,
      in: u.input_tokens, out: u.output_tokens, reasoning: u.output_tokens_details?.reasoning_tokens || 0,
      usd,
    };
  } catch (err) {
    return {
      name: p.name, status: 'FAIL', model,
      error: (err.status ? `${err.status} ` : '') + (err.message || String(err)).split('\n')[0].slice(0, 140),
    };
  }
}

console.log('Probing each agent prompt + realistic user prompt against OpenAI content filter...\n');
let totalUsd = 0;
let failed = 0;
for (const p of PROBES) {
  const r = await probe(p);
  if (r.status === 'PASS') {
    totalUsd += r.usd;
    console.log(`  ${pad(r.name, 12)} PASS  (${pad(r.model, 12)} ${r.in} in / ${r.out} out / ${r.reasoning} reasoning · $${r.usd.toFixed(4)})`);
  } else {
    failed++;
    console.log(`  ${pad(r.name, 12)} FAIL  (${pad(r.model, 12)} ${r.error})`);
  }
}
console.log('');
console.log(failed === 0
  ? `All ${PROBES.length} prompts pass. Approximate cost: $${totalUsd.toFixed(4)}.`
  : `${failed} of ${PROBES.length} prompts FAILED. Reframe and retry.`);

process.exit(failed === 0 ? 0 : 1);
