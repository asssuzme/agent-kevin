import 'dotenv/config';
import { addEndpoint, addSecret } from '../state/targetGraph.js';

const TIMEOUT_MS = Number(process.env.HTTP_TIMEOUT_MS || 15000);
const USER_AGENT = process.env.SCAN_USER_AGENT || 'Vibehack/0.2';
const MAX_BUNDLE_BYTES = 2_000_000;

async function fetchBundle(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const resp = await fetch(url, { signal: controller.signal, headers: { 'User-Agent': USER_AGENT }, redirect: 'follow' });
    if (!resp.ok) return { error: `HTTP ${resp.status}` };
    const buf = await resp.arrayBuffer();
    if (buf.byteLength > MAX_BUNDLE_BYTES) return { error: `bundle too large (${buf.byteLength} bytes)` };
    return { body: Buffer.from(buf).toString('utf8'), size: buf.byteLength };
  } catch (err) {
    return { error: err.name === 'AbortError' ? 'timeout' : (err.message || String(err)) };
  } finally {
    clearTimeout(timer);
  }
}

const ENDPOINT_PATTERNS = [
  /["'`](\/api\/[a-zA-Z0-9/_\-?=&{}[\].:$%]+)["'`]/g,
  /["'`](\/[a-zA-Z0-9_\-]+\/[a-zA-Z0-9/_\-?=&{}[\].:$%]+)["'`]/g,
  /fetch\(\s*["'`]([^"'`]+)["'`]/g,
  /axios\.[a-z]+\(\s*["'`]([^"'`]+)["'`]/g,
  /\.get\(\s*["'`](\/[^"'`]+)["'`]/g,
  /\.post\(\s*["'`](\/[^"'`]+)["'`]/g,
  /\.put\(\s*["'`](\/[^"'`]+)["'`]/g,
  /\.delete\(\s*["'`](\/[^"'`]+)["'`]/g,
  /\.patch\(\s*["'`](\/[^"'`]+)["'`]/g,
  /from\(["'`]([^"'`]+)["'`]\)\s*\./g,
];

const SECRET_PATTERNS = [
  { type: 'SUPABASE_URL',    re: /https:\/\/[a-z0-9]{15,30}\.supabase\.co/g, is_public: true },
  { type: 'SUPABASE_ANON',   re: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, is_public: true, note: 'JWT — could be anon (public) or service-role (CRITICAL leak)' },
  { type: 'CLERK_PUB_KEY',   re: /pk_(?:live|test)_[A-Za-z0-9_-]{20,}/g, is_public: true },
  { type: 'CLERK_FRONTEND',  re: /https:\/\/[a-z0-9-]+\.clerk\.accounts\.dev/g, is_public: true },
  { type: 'STRIPE_PUB',      re: /pk_(?:live|test)_[A-Za-z0-9]{24,}/g, is_public: true },
  { type: 'STRIPE_SECRET',   re: /sk_(?:live|test)_[A-Za-z0-9]{24,}/g, is_public: false, note: 'CRITICAL — Stripe secret key' },
  { type: 'AWS_KEY',         re: /AKIA[A-Z0-9]{16}/g, is_public: false, note: 'CRITICAL — AWS access key' },
  { type: 'GOOGLE_API_KEY',  re: /AIza[A-Za-z0-9_-]{35}/g, is_public: true, note: 'Often restricted to specific APIs/referrers — check at console.cloud.google.com' },
  { type: 'GITHUB_PAT',      re: /ghp_[A-Za-z0-9]{36}/g, is_public: false, note: 'CRITICAL — GitHub personal access token' },
  { type: 'JWT_GENERIC',     re: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, is_public: null },
  { type: 'BEARER_TOKEN',    re: /Bearer\s+[A-Za-z0-9._\-]{20,}/g, is_public: false },
  { type: 'SOURCEMAP_REF',   re: /\/\/[#@]\s*sourceMappingURL\s*=\s*([^\s\n]+)/g, is_public: null, note: 'Source map reference — fetch the .map for full source disclosure' },
  { type: 'OPENAI_KEY',      re: /sk-(?:proj-)?[A-Za-z0-9_-]{40,}/g, is_public: false, note: 'CRITICAL — OpenAI API key' },
  { type: 'POSTGRES_URL',    re: /postgres(?:ql)?:\/\/[^"'\s`]{10,}/g, is_public: false, note: 'CRITICAL — Postgres connection string' },
];

const STACK_HINTS = [
  { re: /__NEXT_DATA__/i, framework: 'Next.js' },
  { re: /_buildManifest/i, framework: 'Next.js' },
  { re: /nuxt/i, framework: 'Nuxt' },
  { re: /\bvite\b/i, framework: 'Vite' },
  { re: /__SVELTEKIT_/i, framework: 'SvelteKit' },
  { re: /react-dom/i, framework: 'React' },
  { re: /vue\.(esm|runtime|common)/i, framework: 'Vue' },
  { re: /window\.angular/i, framework: 'Angular' },
];

function fingerprintFromBody(body) {
  const hits = STACK_HINTS.filter(h => h.re.test(body)).map(h => h.framework);
  return Array.from(new Set(hits));
}

export const extractJsEndpointsTool = {
  schema: {
    type: 'function',
    name: 'extract_js_endpoints',
    description: 'Fetch a JS bundle URL and regex-extract endpoint patterns (fetch/axios/.get/.post calls, /api/* literals). Auto-adds findings to the target graph. Use after locating <script src=...> on the target. Returns count + sample list.',
    parameters: {
      type: 'object',
      properties: {
        url: { type: 'string' },
      },
      required: ['url'],
    },
  },
  dispatch: async (args, ctx) => {
    const r = await fetchBundle(args.url);
    if (r.error) return { error: r.error };
    const seen = new Set();
    for (const re of ENDPOINT_PATTERNS) {
      for (const m of r.body.matchAll(re)) {
        const ep = m[1];
        if (!ep) continue;
        if (ep.length > 300) continue;
        if (/\.(png|jpg|jpeg|svg|gif|webp|woff2?|css|ico)(\?|$)/i.test(ep)) continue;
        seen.add(ep);
      }
    }
    for (const ep of seen) {
      addEndpoint(ctx.jobId, { url: ep, source: `js:${args.url}` });
    }
    const sample = Array.from(seen).slice(0, 50);
    return { source: args.url, size_bytes: r.size, endpoint_count: seen.size, sample };
  },
};

export const extractJsSecretsTool = {
  schema: {
    type: 'function',
    name: 'extract_js_secrets',
    description: 'Fetch a JS bundle and regex-extract secrets: Supabase URL/anon, Clerk keys, Stripe/AWS/GitHub/OpenAI tokens, JWTs, source map references. Auto-adds findings to target graph. Returns list with redacted previews.',
    parameters: {
      type: 'object',
      properties: {
        url: { type: 'string' },
      },
      required: ['url'],
    },
  },
  dispatch: async (args, ctx) => {
    const r = await fetchBundle(args.url);
    if (r.error) return { error: r.error };
    const out = [];
    for (const p of SECRET_PATTERNS) {
      for (const m of r.body.matchAll(p.re)) {
        const value = m[0];
        const captured = m[1] || value;
        addSecret(ctx.jobId, { type: p.type, value: captured, source: `js:${args.url}`, is_public: p.is_public, notes: p.note });
        out.push({ type: p.type, preview: captured.slice(0, 24) + '...' + (captured.length > 30 ? captured.slice(-6) : ''), is_public: p.is_public, note: p.note });
      }
    }
    const stack = fingerprintFromBody(r.body);
    return { source: args.url, size_bytes: r.size, secret_count: out.length, secrets: out, stack_hints: stack };
  },
};

export const jsBundleTools = [extractJsEndpointsTool, extractJsSecretsTool];
