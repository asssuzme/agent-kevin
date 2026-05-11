import { getGraph, setStack, addEndpoint, addSecret, addNote, setAuthState } from '../state/targetGraph.js';

export const readGraphTool = {
  schema: {
    type: 'function',
    name: 'read_target_graph',
    description: 'Read the current shared target graph: stack fingerprint, discovered endpoints, extracted secrets, auth state, cookies, agent notes. Call this at the start of your work to see what other agents have already found. Returns a JSON snapshot.',
    parameters: { type: 'object', properties: {}, required: [] },
  },
  dispatch: async (_, ctx) => {
    const g = getGraph(ctx.jobId);
    if (!g) return { error: 'no graph for this job' };
    return {
      target: g.target,
      stack: g.stack,
      endpoints: g.endpoints,
      secrets: g.secrets.map(s => ({
        id: s.id,
        type: s.type,
        value: s.value,
        source: s.source,
        is_public: s.is_public,
        notes: s.notes,
      })),
      cookies_names: Object.keys(g.cookies),
      auth_state: { logged_in: g.auth_state.logged_in, email: g.auth_state.email, user_id: g.auth_state.user_id, has_jwt: !!g.auth_state.jwt },
      notes: g.notes.slice(-30),
    };
  },
};

export const setStackTool = {
  schema: {
    type: 'function',
    name: 'set_stack',
    description: 'Update the target graph stack fingerprint with what you learned. Use when you positively identify the framework, backend, auth provider, CDN, etc.',
    parameters: {
      type: 'object',
      properties: {
        framework: { type: 'string', description: 'e.g. Next.js 14, Nuxt 3, Django 4.x, Express, Spring Boot' },
        backend: { type: 'string', description: 'e.g. Supabase, Firebase, custom Postgres+Express, Rails+MySQL' },
        auth: { type: 'string', description: 'e.g. Clerk, Auth0, Supabase Auth, custom JWT, NextAuth' },
        cdn: { type: 'string', description: 'e.g. Cloudflare, Vercel, AWS CloudFront, Fastly' },
        server: { type: 'string', description: 'e.g. Vercel, Netlify, AWS Lambda, nginx 1.20, Apache 2.4' },
        confidence: { type: 'string', enum: ['low', 'medium', 'high'] },
      },
      required: [],
    },
  },
  dispatch: async (args, ctx) => {
    setStack(ctx.jobId, args);
    return { ok: true };
  },
};

export const addEndpointTool = {
  schema: {
    type: 'function',
    name: 'add_endpoint',
    description: 'Manually add a discovered endpoint to the target graph. Use when you find one not surfaced by extract_js_endpoints — e.g. via fuzz_paths hit, manual exploration, or a Supabase table you confirmed exists.',
    parameters: {
      type: 'object',
      properties: {
        url: { type: 'string' },
        method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] },
        params: { type: 'array', items: { type: 'string' } },
        source: { type: 'string', description: 'How you found it' },
        auth_required: { type: 'string', enum: ['yes', 'no', 'unknown'] },
        notes: { type: 'string' },
      },
      required: ['url'],
    },
  },
  dispatch: async (args, ctx) => {
    const e = addEndpoint(ctx.jobId, args);
    return { added: !!e, id: e?.id };
  },
};

export const addSecretTool = {
  schema: {
    type: 'function',
    name: 'add_secret',
    description: 'Manually add a discovered secret/credential to the target graph. Use for things not caught by extract_js_secrets — e.g. tokens leaked in error responses, hardcoded in HTML, returned by an exposed endpoint.',
    parameters: {
      type: 'object',
      properties: {
        type: { type: 'string', description: 'e.g. STRIPE_SECRET, AWS_KEY, DB_CONNECTION_STRING, INTERNAL_API_TOKEN, SUPABASE_SERVICE_ROLE' },
        value: { type: 'string' },
        source: { type: 'string', description: 'Where you found it (URL, request, response body, error)' },
        is_public: { type: 'boolean', description: 'true if intended-public (anon key, publishable key); false if leaked-private (sk_live, service_role); null if unknown' },
        notes: { type: 'string' },
      },
      required: ['type', 'value', 'source'],
    },
  },
  dispatch: async (args, ctx) => {
    const s = addSecret(ctx.jobId, args);
    return { added: !!s, id: s?.id };
  },
};

export const addNoteTool = {
  schema: {
    type: 'function',
    name: 'add_note',
    description: 'Leave a short note for other agents/the reflection pass. Use for "smelled blood but didn\'t bite" leads — interesting signals you saw but didn\'t pursue, that another agent might want to chase.',
    parameters: {
      type: 'object',
      properties: {
        note: { type: 'string' },
      },
      required: ['note'],
    },
  },
  dispatch: async (args, ctx) => {
    addNote(ctx.jobId, ctx.agentName, args.note);
    return { ok: true };
  },
};

export const setAuthStateTool = {
  schema: {
    type: 'function',
    name: 'set_auth_state',
    description: 'Update the shared auth state after a successful login/registration. Other agents can then make authenticated requests via cookies that the http tools auto-attach.',
    parameters: {
      type: 'object',
      properties: {
        logged_in: { type: 'boolean' },
        jwt: { type: 'string' },
        session_cookie: { type: 'string' },
        user_id: { type: 'string' },
        email: { type: 'string' },
      },
      required: ['logged_in'],
    },
  },
  dispatch: async (args, ctx) => {
    setAuthState(ctx.jobId, args);
    return { ok: true };
  },
};

export const graphTools = [readGraphTool, setStackTool, addEndpointTool, addSecretTool, addNoteTool, setAuthStateTool];
