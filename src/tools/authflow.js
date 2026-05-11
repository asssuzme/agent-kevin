import 'dotenv/config';
import { setAuthState, setCookie, getGraph } from '../state/targetGraph.js';

const TIMEOUT_MS = Number(process.env.HTTP_TIMEOUT_MS || 15000);
const USER_AGENT = process.env.SCAN_USER_AGENT || 'Vibehack/0.2';

function randomSuffix() {
  return Math.random().toString(36).slice(2, 10);
}

function pickJwtFromText(text) {
  if (!text) return null;
  const m = text.match(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/);
  return m ? m[0] : null;
}

async function fetchWithCookies(jobId, url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  const g = getGraph(jobId);
  const cookieStr = g ? Object.entries(g.cookies).filter(([_, v]) => v).map(([k, v]) => `${k}=${v}`).join('; ') : '';
  const headers = { 'User-Agent': USER_AGENT, ...(options.headers || {}) };
  if (cookieStr) headers.Cookie = cookieStr;
  try {
    const resp = await fetch(url, { ...options, headers, redirect: 'follow', signal: controller.signal });
    const respHeaders = Object.fromEntries(resp.headers.entries());
    const sc = respHeaders['set-cookie'];
    if (sc && g) {
      const cookies = Array.isArray(sc) ? sc : [sc];
      for (const c of cookies) {
        const [pair] = c.split(';');
        const eq = pair.indexOf('=');
        if (eq > 0) setCookie(jobId, pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
      }
    }
    const buf = await resp.arrayBuffer();
    const body = Buffer.from(buf).toString('utf8').slice(0, 50000);
    return { status: resp.status, headers: respHeaders, body };
  } catch (err) {
    return { error: err.name === 'AbortError' ? 'timeout' : (err.message || String(err)) };
  } finally {
    clearTimeout(timer);
  }
}

export const registerAccountTool = {
  schema: {
    type: 'function',
    name: 'register_account',
    description: 'Attempt to register a test account on the target. Auto-generates email "vibehack+<rand>@yopmail.com" unless override provided. POSTs the signup body. Captures any Set-Cookie + JWT in response body. Updates auth_state if successful. Returns full response so you can inspect what came back.',
    parameters: {
      type: 'object',
      properties: {
        signup_url: { type: 'string', description: 'Full URL of the signup endpoint, e.g. https://target.com/api/auth/signup' },
        method: { type: 'string', enum: ['POST', 'PUT'] },
        content_type: { type: 'string', description: "Default 'application/json'. Use 'application/x-www-form-urlencoded' or 'multipart/form-data' if API expects that." },
        body_template: { type: 'string', description: 'JSON template using {EMAIL} and {PASSWORD} placeholders, e.g. \'{"email":"{EMAIL}","password":"{PASSWORD}","name":"Vibehack Tester"}\'.' },
        email_override: { type: 'string', description: 'Optional explicit email. Otherwise auto-generated.' },
        password_override: { type: 'string', description: 'Optional explicit password. Otherwise auto-generated.' },
      },
      required: ['signup_url', 'body_template'],
    },
  },
  dispatch: async (args, ctx) => {
    const email = args.email_override || `vibehack+${randomSuffix()}@yopmail.com`;
    const password = args.password_override || `Vh!${randomSuffix()}_A1`;
    const body = args.body_template.replace(/\{EMAIL\}/g, email).replace(/\{PASSWORD\}/g, password);
    const ct = args.content_type || 'application/json';
    const r = await fetchWithCookies(ctx.jobId, args.signup_url, {
      method: args.method || 'POST',
      headers: { 'Content-Type': ct },
      body,
    });
    if (r.error) return { error: r.error, email, password };

    const jwt = pickJwtFromText(r.body);
    const success = r.status >= 200 && r.status < 300;
    if (success) {
      setAuthState(ctx.jobId, {
        logged_in: true,
        email,
        password,
        jwt,
      });
    }
    return {
      status: r.status,
      success,
      email,
      password,
      jwt_captured: !!jwt,
      jwt_preview: jwt ? jwt.slice(0, 24) + '...' + jwt.slice(-6) : null,
      body_preview: (r.body || '').slice(0, 800),
    };
  },
};

export const loginAccountTool = {
  schema: {
    type: 'function',
    name: 'login_account',
    description: 'Attempt login on the target. Use credentials previously captured by register_account (read them from the target graph auth_state) or test credentials if you have a hint. Captures session cookie and JWT. Updates auth_state on success.',
    parameters: {
      type: 'object',
      properties: {
        login_url: { type: 'string' },
        method: { type: 'string', enum: ['POST', 'PUT'] },
        content_type: { type: 'string' },
        body_template: { type: 'string', description: 'Body template with {EMAIL} and {PASSWORD} placeholders.' },
        email: { type: 'string', description: 'Explicit email — usually pulled from auth_state.email from a prior register_account call.' },
        password: { type: 'string' },
      },
      required: ['login_url', 'body_template', 'email', 'password'],
    },
  },
  dispatch: async (args, ctx) => {
    const body = args.body_template.replace(/\{EMAIL\}/g, args.email).replace(/\{PASSWORD\}/g, args.password);
    const ct = args.content_type || 'application/json';
    const r = await fetchWithCookies(ctx.jobId, args.login_url, {
      method: args.method || 'POST',
      headers: { 'Content-Type': ct },
      body,
    });
    if (r.error) return { error: r.error };
    const jwt = pickJwtFromText(r.body);
    const success = r.status >= 200 && r.status < 300;
    if (success) {
      setAuthState(ctx.jobId, { logged_in: true, email: args.email, password: args.password, jwt });
    }
    return {
      status: r.status,
      success,
      jwt_captured: !!jwt,
      jwt_preview: jwt ? jwt.slice(0, 24) + '...' + jwt.slice(-6) : null,
      body_preview: (r.body || '').slice(0, 800),
    };
  },
};

export const authenticatedRequestTool = {
  schema: {
    type: 'function',
    name: 'authenticated_request',
    description: 'Make a request with the captured session cookies AND any JWT auth_state has. Use this (not http_get/http_post) when you need authenticated access. Returns status, headers, body, timing.',
    parameters: {
      type: 'object',
      properties: {
        url: { type: 'string' },
        method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] },
        body: { type: 'string' },
        content_type: { type: 'string' },
        extra_headers: { type: 'object', additionalProperties: { type: 'string' } },
      },
      required: ['url'],
    },
  },
  dispatch: async (args, ctx) => {
    const g = getGraph(ctx.jobId);
    const headers = { ...(args.extra_headers || {}) };
    if (args.body && args.content_type) headers['Content-Type'] = args.content_type;
    if (g?.auth_state?.jwt) headers.Authorization = `Bearer ${g.auth_state.jwt}`;
    const started = Date.now();
    const r = await fetchWithCookies(ctx.jobId, args.url, {
      method: args.method || 'GET',
      headers,
      body: args.body,
    });
    const timing_ms = Date.now() - started;
    if (r.error) return { error: r.error, timing_ms };
    return { status: r.status, headers: r.headers, body: r.body, timing_ms };
  },
};

export const authflowTools = [registerAccountTool, loginAccountTool, authenticatedRequestTool];
