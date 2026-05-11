import 'dotenv/config';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const wordlistsDir = join(__dirname, '..', 'wordlists');
const TIMEOUT_MS = Number(process.env.HTTP_TIMEOUT_MS || 15000);
const USER_AGENT = process.env.SCAN_USER_AGENT || 'Vibehack/0.2';

const wordlistCache = new Map();

async function loadWordlist(name) {
  if (wordlistCache.has(name)) return wordlistCache.get(name);
  const safe = name.replace(/[^a-z0-9_-]/g, '');
  const body = await readFile(join(wordlistsDir, `${safe}.txt`), 'utf8');
  const words = body.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  wordlistCache.set(name, words);
  return words;
}

async function quickHead(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  const started = Date.now();
  try {
    let resp = await fetch(url, { method: 'HEAD', signal: controller.signal, headers: { 'User-Agent': USER_AGENT }, redirect: 'follow' });
    if (resp.status === 405) {
      resp = await fetch(url, { method: 'GET', signal: controller.signal, headers: { 'User-Agent': USER_AGENT, Range: 'bytes=0-512' }, redirect: 'follow' });
    }
    return { status: resp.status, size: Number(resp.headers.get('content-length')) || null, timing_ms: Date.now() - started };
  } catch (err) {
    return { error: err.name === 'AbortError' ? 'timeout' : (err.message || String(err)), timing_ms: Date.now() - started };
  } finally {
    clearTimeout(timer);
  }
}

export const fuzzPathsTool = {
  schema: {
    type: 'function',
    name: 'fuzz_paths',
    description: 'Batch-probe a curated wordlist of paths against the target base URL. Returns only paths that responded with non-404 status. Use this early in recon to find exposed files, admin endpoints, debug routes. wordlist="common-paths" gives ~200 paths covering .env, .git/*, /api/*, /admin, /actuator/env, _next/data, supabase rest endpoints, etc. Concurrent and fast.',
    parameters: {
      type: 'object',
      properties: {
        base_url: { type: 'string', description: 'Origin or base path, e.g. https://target.com' },
        wordlist: { type: 'string', description: 'wordlist name without .txt — "common-paths" is the main one', enum: ['common-paths', 'supabase-tables'] },
        max: { type: 'number', description: 'Optional cap on how many paths to test (default all in wordlist).' },
      },
      required: ['base_url', 'wordlist'],
    },
  },
  dispatch: async (args) => {
    const words = await loadWordlist(args.wordlist);
    const limit = args.max || words.length;
    const slice = words.slice(0, limit);
    const base = args.base_url.replace(/\/$/, '');

    const CONCURRENCY = 16;
    const results = [];
    let i = 0;
    async function worker() {
      while (true) {
        const idx = i++;
        if (idx >= slice.length) return;
        const path = slice[idx];
        const url = `${base}/${path}`;
        const r = await quickHead(url);
        if (!r.error && r.status && r.status !== 404 && r.status !== 0) {
          results.push({ path, status: r.status, size: r.size });
        }
      }
    }
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));
    results.sort((a, b) => a.status - b.status || a.path.localeCompare(b.path));
    return {
      base_url: base,
      wordlist: args.wordlist,
      tested: slice.length,
      hit_count: results.length,
      hits: results,
    };
  },
};

export const fuzzParamsTool = {
  schema: {
    type: 'function',
    name: 'fuzz_params',
    description: 'Try adding common param names (id, debug, admin, redirect, file, etc.) to a URL and report which ones produce response changes vs the baseline. Useful for finding hidden parameters that influence behavior.',
    parameters: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'URL to test — should be a real path on the target' },
        max: { type: 'number', description: 'Cap on how many params to test (default ~80)' },
      },
      required: ['url'],
    },
  },
  dispatch: async (args) => {
    const params = await loadWordlist('common-params');
    const limit = args.max || params.length;
    const slice = params.slice(0, limit);

    const baseline = await (async () => {
      const r = await fetch(args.url, { headers: { 'User-Agent': USER_AGENT }, redirect: 'follow' });
      const buf = await r.arrayBuffer();
      return { status: r.status, size: buf.byteLength };
    })().catch(e => ({ error: e.message }));

    if (baseline.error) return { error: baseline.error };

    const CONCURRENCY = 12;
    const hits = [];
    let i = 0;
    async function worker() {
      while (true) {
        const idx = i++;
        if (idx >= slice.length) return;
        const p = slice[idx];
        const sep = args.url.includes('?') ? '&' : '?';
        const testUrl = `${args.url}${sep}${encodeURIComponent(p)}=vibehack`;
        try {
          const r = await fetch(testUrl, { headers: { 'User-Agent': USER_AGENT }, redirect: 'follow' });
          const buf = await r.arrayBuffer();
          if (r.status !== baseline.status || Math.abs(buf.byteLength - baseline.size) > 30) {
            hits.push({ param: p, status: r.status, size_delta: buf.byteLength - baseline.size });
          }
        } catch {}
      }
    }
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));
    return {
      url: args.url,
      baseline,
      tested: slice.length,
      hit_count: hits.length,
      candidates: hits.slice(0, 30),
    };
  },
};

export const fuzzTools = [fuzzPathsTool, fuzzParamsTool];
