import * as recon from './agents/recon.js';
import * as injection from './agents/injection.js';
import * as authAgent from './agents/auth.js';
import * as xss from './agents/xss.js';
import * as ssrf from './agents/ssrf.js';
import * as misconfig from './agents/misconfig.js';
import * as supabase from './agents/supabase.js';
import * as clerk from './agents/clerk.js';
import * as graphql from './agents/graphql.js';
import * as nextjs from './agents/nextjs.js';
import * as reflection from './agents/reflection.js';
import * as aggregator from './aggregator.js';
import { createGraph, getGraph, deleteGraph } from './state/targetGraph.js';
import { createMeter, getMeter, deleteMeter } from './cost.js';

const MAX_CONCURRENT_SCANS = Number(process.env.MAX_CONCURRENT_SCANS || 3);

const jobs = new Map();
let active = 0;
const queue = [];

function makeId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

export function createJob(targetUrl, options = {}) {
  const id = makeId();
  const job = {
    id,
    target: targetUrl,
    createdAt: new Date().toISOString(),
    status: 'queued',
    phase: null,
    options,
    events: [],
    findings: [],
    reconSummary: null,
    report: null,
    reportPath: null,
    error: null,
    subscribers: new Set(),
  };
  jobs.set(id, job);

  const start = () => {
    active++;
    runScan(job).catch(err => {
      job.status = 'error';
      job.error = err.message || String(err);
      emit(job, { type: 'error', error: job.error });
    }).finally(() => {
      active--;
      emit(job, { type: 'closed' });
      setTimeout(() => {
        deleteGraph(job.id);
        deleteMeter(job.id);
      }, 60 * 1000);
      while (queue.length && active < MAX_CONCURRENT_SCANS) {
        const next = queue.shift();
        next();
      }
    });
  };

  if (active < MAX_CONCURRENT_SCANS) start();
  else queue.push(start);

  return job;
}

export function getJob(id) { return jobs.get(id); }

export function subscribe(job, fn) {
  job.subscribers.add(fn);
  for (const ev of job.events) fn(ev);
  return () => job.subscribers.delete(fn);
}

function emit(job, event) {
  const ev = { ...event, ts: new Date().toISOString() };
  job.events.push(ev);
  for (const fn of job.subscribers) {
    try { fn(ev); } catch {}
  }
}

async function runScan(job) {
  job.status = 'running';
  createGraph(job.id, job.target);
  createMeter(job.id);

  const onEvent = (ev) => {
    if (ev.type === 'usage') {
      const m = getMeter(job.id);
      if (m) emit(job, { type: 'cost_update', total_usd: m.totalUsd, total_reasoning: m.totalReasoning, by_model: Object.fromEntries(Object.entries(m.byModel).map(([k, v]) => [k, { calls: v.calls, usd: v.usd }])) });
    }
    if (['endpoint', 'secret', 'stack', 'auth_state'].some(t => ev.type === t)) {
      // ignore — internal graph history (we'll snapshot the graph instead)
    }
    if (ev.type === 'finding' || ev.type === 'tool_call' || ev.type === 'reasoning' || ev.type === 'think' || ev.type === 'replan' || ev.type === 'tool_result' || ev.type === 'agent_started' || ev.type === 'agent_completed' || ev.type === 'agent_error' || ev.type === 'usage') {
      emit(job, ev);
    }
  };

  // PASS 1 — recon
  emit(job, { type: 'phase', phase: 'recon' });
  job.phase = 'recon';
  job.reconSummary = await recon.run({ target: job.target, jobId: job.id, onEvent });
  emit(job, { type: 'graph_update', summary: graphSummary(job.id) });

  // PASS 2 — generic specialists (parallel)
  emit(job, { type: 'phase', phase: 'specialists' });
  job.phase = 'specialists';
  const tryRegister = !!job.options.tryRegister;
  const genericResults = await Promise.allSettled([
    injection.run({ target: job.target, reconSummary: job.reconSummary, jobId: job.id, onEvent }),
    authAgent.run({ target: job.target, reconSummary: job.reconSummary, jobId: job.id, tryRegister, onEvent }),
    xss.run({ target: job.target, reconSummary: job.reconSummary, jobId: job.id, onEvent }),
    ssrf.run({ target: job.target, reconSummary: job.reconSummary, jobId: job.id, onEvent }),
    misconfig.run({ target: job.target, reconSummary: job.reconSummary, jobId: job.id, onEvent }),
  ]);
  for (const r of genericResults) {
    if (r.status === 'fulfilled' && Array.isArray(r.value)) job.findings.push(...r.value);
  }
  emit(job, { type: 'graph_update', summary: graphSummary(job.id) });

  // PASS 3 — stack-aware specialists (gated)
  emit(job, { type: 'phase', phase: 'stack_specialists' });
  job.phase = 'stack_specialists';
  const graph = getGraph(job.id);
  const stackAgents = [];
  if (supabase.shouldFire(graph)) stackAgents.push(['supabase', supabase.run({ target: job.target, reconSummary: job.reconSummary, jobId: job.id, onEvent })]);
  if (clerk.shouldFire(graph)) stackAgents.push(['clerk', clerk.run({ target: job.target, reconSummary: job.reconSummary, jobId: job.id, tryRegister, onEvent })]);
  if (graphql.shouldFire(graph)) stackAgents.push(['graphql', graphql.run({ target: job.target, reconSummary: job.reconSummary, jobId: job.id, onEvent })]);
  if (nextjs.shouldFire(graph)) stackAgents.push(['nextjs', nextjs.run({ target: job.target, reconSummary: job.reconSummary, jobId: job.id, onEvent })]);

  emit(job, { type: 'stack_specialists_firing', agents: stackAgents.map(([n]) => n) });

  if (stackAgents.length) {
    const stackResults = await Promise.allSettled(stackAgents.map(([_, p]) => p));
    for (const r of stackResults) {
      if (r.status === 'fulfilled' && Array.isArray(r.value)) job.findings.push(...r.value);
    }
  }
  emit(job, { type: 'graph_update', summary: graphSummary(job.id) });

  // PASS 4 — reflection
  emit(job, { type: 'phase', phase: 'reflection' });
  job.phase = 'reflection';
  try {
    const reflectionFindings = await reflection.run({
      target: job.target,
      reconSummary: job.reconSummary,
      jobId: job.id,
      allFindings: job.findings,
      onEvent,
    });
    job.findings.push(...reflectionFindings);
  } catch (err) {
    emit(job, { type: 'reflection_error', error: err.message || String(err) });
  }

  // PASS 5 — aggregator (render report)
  emit(job, { type: 'phase', phase: 'aggregating' });
  job.phase = 'aggregating';
  const { report, reportPath } = await aggregator.render({
    target: job.target,
    reconSummary: job.reconSummary,
    findings: job.findings,
    scanId: job.id,
    graphSnapshot: getGraph(job.id),
    costSummary: getMeter(job.id),
  });
  job.report = report;
  job.reportPath = reportPath;

  job.status = 'done';
  job.phase = 'done';
  const meter = getMeter(job.id);
  emit(job, { type: 'done', report, reportPath, findings_count: job.findings.length, total_usd: meter?.totalUsd || 0 });
}

function graphSummary(jobId) {
  const g = getGraph(jobId);
  if (!g) return null;
  return {
    stack: g.stack,
    endpoint_count: g.endpoints.length,
    endpoints_preview: g.endpoints.slice(0, 30).map(e => ({ method: e.method, url: e.url })),
    secret_count: g.secrets.length,
    secrets_preview: g.secrets.slice(0, 20).map(s => ({ type: s.type, is_public: s.is_public, preview: (s.value || '').slice(0, 24) + '...' })),
    auth_state: { logged_in: g.auth_state.logged_in, email: g.auth_state.email },
    notes_count: g.notes.length,
  };
}
