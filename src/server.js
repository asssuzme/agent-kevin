import 'dotenv/config';
import express from 'express';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createJob, getJob, subscribe } from './orchestrator.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);

const app = express();

// Optional basic-auth gate. Enabled only if BOTH env vars set.
// Useful for any internet-exposed deployment.
if (process.env.ACCESS_USER && process.env.ACCESS_PASSWORD) {
  const expected = 'Basic ' + Buffer.from(`${process.env.ACCESS_USER}:${process.env.ACCESS_PASSWORD}`).toString('base64');
  app.use((req, res, next) => {
    if (req.headers.authorization === expected) return next();
    res.set('WWW-Authenticate', 'Basic realm="Agent Kevin"');
    res.status(401).send('Authentication required');
  });
  console.log(`[auth] Basic auth enabled for user "${process.env.ACCESS_USER}"`);
}

app.use(express.json({ limit: '1mb' }));
app.use(express.static(join(__dirname, '..', 'public')));

app.get('/healthz', (req, res) => res.json({ ok: true, service: 'agent-kevin', version: '2.1' }));

app.post('/api/scan', (req, res) => {
  const { url, tryRegister } = req.body || {};
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'POST body must include `url` (string)' });
  }
  let target;
  try {
    target = new URL(url);
  } catch {
    return res.status(400).json({ error: 'Invalid URL' });
  }
  if (!['http:', 'https:'].includes(target.protocol)) {
    return res.status(400).json({ error: 'URL must be http: or https:' });
  }
  const job = createJob(target.toString(), { tryRegister: !!tryRegister });
  res.json({ id: job.id, status: job.status, target: job.target, options: job.options });
});

app.get('/api/scan/:id', (req, res) => {
  const job = getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'job not found' });
  const { subscribers, ...safe } = job;
  res.json(safe);
});

app.get('/api/scan/:id/events', (req, res) => {
  const job = getJob(req.params.id);
  if (!job) return res.status(404).end();

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();

  const send = (ev) => {
    res.write(`data: ${JSON.stringify(ev)}\n\n`);
    if (ev.type === 'closed') res.end();
  };

  const unsub = subscribe(job, send);
  const ping = setInterval(() => res.write(`: ping\n\n`), 15000);

  req.on('close', () => {
    clearInterval(ping);
    unsub();
  });
});

app.get('/api/scan/:id/report', (req, res) => {
  const job = getJob(req.params.id);
  if (!job) return res.status(404).end();
  if (!job.report) return res.status(409).json({ error: 'report not ready', status: job.status, phase: job.phase });
  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="agent-kevin-${job.id}.md"`);
  res.send(job.report);
});

app.listen(PORT, () => {
  console.log(`Agent Kevin running on http://localhost:${PORT}`);
});
