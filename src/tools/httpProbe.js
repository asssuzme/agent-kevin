import 'dotenv/config';
import { getGraph, setCookie } from '../state/targetGraph.js';

const TIMEOUT_MS = Number(process.env.HTTP_TIMEOUT_MS || 15000);
const USER_AGENT = process.env.SCAN_USER_AGENT || 'Vibehack/0.2';
const MAX_BODY_BYTES = 50_000;

function mergeCookies(jobId, headers = {}) {
  const g = getGraph(jobId);
  if (!g) return headers;
  const cookies = Object.entries(g.cookies).filter(([_, v]) => v);
  if (!cookies.length) return headers;
  const existing = headers.Cookie || headers.cookie || '';
  const cookieStr = cookies.map(([k, v]) => `${k}=${v}`).join('; ');
  return { ...headers, Cookie: existing ? `${existing}; ${cookieStr}` : cookieStr };
}

function captureSetCookies(jobId, resp) {
  const setCookies = resp.headers.raw?.()?.['set-cookie'] || [];
  if (!Array.isArray(setCookies)) return;
  for (const sc of setCookies) {
    const [pair] = sc.split(';');
    const eq = pair.indexOf('=');
    if (eq > 0) {
      setCookie(jobId, pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
  }
}

async function doFetch(url, options = {}, jobId = null) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  const started = Date.now();
  try {
    const headers = mergeCookies(jobId, { 'User-Agent': USER_AGENT, ...(options.headers || {}) });
    const resp = await fetch(url, { ...options, redirect: 'follow', signal: controller.signal, headers });
    const timing_ms = Date.now() - started;
    const respHeaders = Object.fromEntries(resp.headers.entries());

    if (jobId && respHeaders['set-cookie']) {
      const sc = respHeaders['set-cookie'];
      const cookies = Array.isArray(sc) ? sc : [sc];
      for (const c of cookies) {
        const [pair] = c.split(';');
        const eq = pair.indexOf('=');
        if (eq > 0) setCookie(jobId, pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
      }
    }

    const buf = await resp.arrayBuffer();
    let body = Buffer.from(buf).toString('utf8');
    const truncated = body.length > MAX_BODY_BYTES;
    if (truncated) body = body.slice(0, MAX_BODY_BYTES) + `\n... [truncated ${buf.byteLength - MAX_BODY_BYTES} bytes]`;
    return { status: resp.status, url: resp.url, timing_ms, headers: respHeaders, body, truncated };
  } catch (err) {
    const timing_ms = Date.now() - started;
    return { error: err.name === 'AbortError' ? `timeout after ${TIMEOUT_MS}ms` : (err.message || String(err)), timing_ms };
  } finally {
    clearTimeout(timer);
  }
}

export const httpGetTool = {
  schema: {
    type: 'function',
    name: 'http_get',
    description: 'HTTP GET. Returns status, headers, body (truncated 50KB), timing ms. Cookies from auth_state in the target graph are auto-attached.',
    parameters: {
      type: 'object',
      properties: {
        url: { type: 'string' },
        headers: { type: 'object', additionalProperties: { type: 'string' } },
      },
      required: ['url'],
    },
  },
  dispatch: async (args, ctx) => doFetch(args.url, { method: 'GET', headers: args.headers }, ctx.jobId),
};

export const httpPostTool = {
  schema: {
    type: 'function',
    name: 'http_post',
    description: 'HTTP POST. body is a raw string (JSON, form-encoded, etc — encode yourself). content_type defaults to application/x-www-form-urlencoded.',
    parameters: {
      type: 'object',
      properties: {
        url: { type: 'string' },
        body: { type: 'string' },
        content_type: { type: 'string' },
        headers: { type: 'object', additionalProperties: { type: 'string' } },
      },
      required: ['url', 'body'],
    },
  },
  dispatch: async (args, ctx) => doFetch(args.url, {
    method: 'POST',
    headers: { 'Content-Type': args.content_type || 'application/x-www-form-urlencoded', ...(args.headers || {}) },
    body: args.body,
  }, ctx.jobId),
};

export const httpHeadTool = {
  schema: {
    type: 'function',
    name: 'http_head',
    description: 'HTTP HEAD. Cheap fingerprinting — server headers, security headers, redirects without downloading body.',
    parameters: {
      type: 'object',
      properties: {
        url: { type: 'string' },
        headers: { type: 'object', additionalProperties: { type: 'string' } },
      },
      required: ['url'],
    },
  },
  dispatch: async (args, ctx) => doFetch(args.url, { method: 'HEAD', headers: args.headers }, ctx.jobId),
};

export const responseDiffTool = {
  schema: {
    type: 'function',
    name: 'response_diff',
    description: 'GET two URLs and compare. Primary tool for boolean-based and time-based detection. Pass baseline_url (e.g. ?id=1) and test_url (e.g. ?id=1+AND+SLEEP(5)). likely_time_based_vuln flips true when timing_delta_ms > 3500.',
    parameters: {
      type: 'object',
      properties: {
        baseline_url: { type: 'string' },
        test_url: { type: 'string' },
        headers: { type: 'object', additionalProperties: { type: 'string' } },
      },
      required: ['baseline_url', 'test_url'],
    },
  },
  dispatch: async (args, ctx) => {
    const [a, b] = await Promise.all([
      doFetch(args.baseline_url, { method: 'GET', headers: args.headers }, ctx.jobId),
      doFetch(args.test_url, { method: 'GET', headers: args.headers }, ctx.jobId),
    ]);
    if (a.error || b.error) return { baseline: a, test: b, diff: 'one or both errored' };
    const sizeDelta = (b.body?.length || 0) - (a.body?.length || 0);
    const timingDelta = b.timing_ms - a.timing_ms;
    return {
      baseline: { status: a.status, timing_ms: a.timing_ms, size: a.body?.length || 0, snippet: (a.body || '').slice(0, 400) },
      test:     { status: b.status, timing_ms: b.timing_ms, size: b.body?.length || 0, snippet: (b.body || '').slice(0, 400) },
      diff: {
        status_changed: a.status !== b.status,
        size_delta_bytes: sizeDelta,
        timing_delta_ms: timingDelta,
        likely_time_based_vuln: timingDelta > 3500,
        likely_boolean_based_vuln: Math.abs(sizeDelta) > 50 || a.status !== b.status,
      },
    };
  },
};

export const httpTools = [httpGetTool, httpPostTool, httpHeadTool, responseDiffTool];
