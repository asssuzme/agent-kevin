const graphs = new Map();

function makeId(prefix) {
  return `${prefix}_${Math.random().toString(36).slice(2, 8)}`;
}

export function createGraph(jobId, target) {
  const graph = {
    target,
    stack: { framework: null, backend: null, auth: null, cdn: null, server: null, confidence: 'unknown' },
    endpoints: [],
    secrets: [],
    cookies: {},
    auth_state: { logged_in: false, jwt: null, session_cookie: null, user_id: null, email: null, password: null },
    notes: [],
    history: [],
  };
  graphs.set(jobId, graph);
  return graph;
}

export function getGraph(jobId) {
  return graphs.get(jobId);
}

export function setStack(jobId, partial) {
  const g = graphs.get(jobId); if (!g) return;
  Object.assign(g.stack, partial);
  g.history.push({ type: 'stack', at: new Date().toISOString(), partial });
}

export function addEndpoint(jobId, ep) {
  const g = graphs.get(jobId); if (!g) return null;
  if (!ep.url) return null;
  const dup = g.endpoints.find(e => e.url === ep.url && (e.method || 'GET') === (ep.method || 'GET'));
  if (dup) {
    if (ep.params) dup.params = Array.from(new Set([...(dup.params || []), ...ep.params]));
    if (ep.source && !dup.sources?.includes(ep.source)) {
      dup.sources = dup.sources || [];
      dup.sources.push(ep.source);
    }
    return dup;
  }
  const entry = {
    id: makeId('e'),
    method: ep.method || 'GET',
    url: ep.url,
    params: ep.params || [],
    sources: ep.source ? [ep.source] : [],
    auth_required: ep.auth_required || 'unknown',
    notes: ep.notes || '',
  };
  g.endpoints.push(entry);
  g.history.push({ type: 'endpoint', at: new Date().toISOString(), id: entry.id, url: entry.url });
  return entry;
}

export function addSecret(jobId, sec) {
  const g = graphs.get(jobId); if (!g) return null;
  if (!sec.value) return null;
  const dup = g.secrets.find(s => s.value === sec.value);
  if (dup) return dup;
  const entry = {
    id: makeId('s'),
    type: sec.type || 'UNKNOWN',
    value: sec.value,
    source: sec.source || 'unknown',
    is_public: sec.is_public ?? null,
    notes: sec.notes || '',
  };
  g.secrets.push(entry);
  g.history.push({ type: 'secret', at: new Date().toISOString(), id: entry.id, secretType: entry.type });
  return entry;
}

export function addNote(jobId, agent, note) {
  const g = graphs.get(jobId); if (!g) return;
  g.notes.push({ agent, note, at: new Date().toISOString() });
}

export function setAuthState(jobId, partial) {
  const g = graphs.get(jobId); if (!g) return;
  Object.assign(g.auth_state, partial);
  g.history.push({ type: 'auth_state', at: new Date().toISOString(), logged_in: g.auth_state.logged_in });
}

export function setCookie(jobId, name, value) {
  const g = graphs.get(jobId); if (!g) return;
  g.cookies[name] = value;
}

export function summarize(jobId) {
  const g = graphs.get(jobId); if (!g) return null;
  return {
    target: g.target,
    stack: g.stack,
    endpoint_count: g.endpoints.length,
    secret_count: g.secrets.length,
    auth_state: { logged_in: g.auth_state.logged_in, email: g.auth_state.email },
  };
}

export function deleteGraph(jobId) {
  graphs.delete(jobId);
}
