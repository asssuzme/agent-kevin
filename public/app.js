const form = document.getElementById('scan-form');
const targetInput = document.getElementById('target-url');
const tryRegisterEl = document.getElementById('try-register');
const scanBtn = document.getElementById('scan-btn');
const scanBtnLabel = scanBtn.querySelector('.btn-label');

const statusSection = document.getElementById('status-section');
const reportSection = document.getElementById('report-section');

const phaseEls = document.querySelectorAll('.phase');
const agentsGrid = document.getElementById('agents-grid');
const agentsMeta = document.getElementById('agents-meta');
const reportMd = document.getElementById('report-md');
const copyBtn = document.getElementById('copy-btn');
const downloadLink = document.getElementById('download-link');

const liveDot = document.getElementById('live-dot');
const liveLabel = document.getElementById('live-label');

const countEls = {
  critical: document.getElementById('ct-critical'),
  high: document.getElementById('ct-high'),
  medium: document.getElementById('ct-medium'),
  low: document.getElementById('ct-low'),
};

const costValEl = document.getElementById('cost-val');
const costSubEl = document.getElementById('cost-sub');
const costBlockEl = costValEl.closest('.stat-block');

const gStackEl = document.getElementById('g-stack');
const gEndpointsEl = document.getElementById('g-endpoints');
const gSecretsEl = document.getElementById('g-secrets');
const gAuthEl = document.getElementById('g-auth');
const gEpCountEl = document.getElementById('g-ep-count');
const gSecCountEl = document.getElementById('g-sec-count');

const feedListEl = document.getElementById('feed-list');
const feedCountEl = document.getElementById('feed-count');

const AGENT_NAMES = ['recon', 'injection', 'auth', 'xss', 'ssrf', 'misconfig', 'supabase', 'clerk', 'graphql', 'nextjs', 'reflection'];
const counts = { critical: 0, high: 0, medium: 0, low: 0 };
const SOFT_WARN_USD = 5;

let feedCounter = 0;
const MAX_FEED_ITEMS = 60;
let costAnim = { current: 0, target: 0, raf: null };

function reset() {
  statusSection.hidden = true;
  reportSection.hidden = true;
  agentsGrid.innerHTML = '';
  feedListEl.innerHTML = '';
  feedCounter = 0;
  feedCountEl.textContent = '0';
  reportMd.textContent = '';
  for (const el of phaseEls) el.classList.remove('active', 'complete');
  for (const k of Object.keys(counts)) counts[k] = 0;
  updateCounts();
  costValEl.textContent = '$0.0000';
  costSubEl.textContent = '0 reasoning tokens';
  costBlockEl.classList.remove('cost-warn');
  gStackEl.textContent = 'unknown';
  gEndpointsEl.innerHTML = '';
  gSecretsEl.innerHTML = '';
  gAuthEl.textContent = 'not logged in';
  gEpCountEl.textContent = '0';
  gSecCountEl.textContent = '0';
  setIdle();
}

function setLive(label) {
  liveDot.classList.add('live');
  liveLabel.textContent = label;
}
function setIdle(label = 'Idle') {
  liveDot.classList.remove('live');
  liveLabel.textContent = label;
}

function updateCounts() {
  countEls.critical.textContent = counts.critical;
  countEls.high.textContent = counts.high;
  countEls.medium.textContent = counts.medium;
  countEls.low.textContent = counts.low;
}

function animateCost(target) {
  costAnim.target = target;
  if (costAnim.raf) return;
  const step = () => {
    const diff = costAnim.target - costAnim.current;
    if (Math.abs(diff) < 0.0001) {
      costAnim.current = costAnim.target;
      costValEl.textContent = `$${costAnim.current.toFixed(4)}`;
      costAnim.raf = null;
      return;
    }
    costAnim.current += diff * 0.18;
    costValEl.textContent = `$${costAnim.current.toFixed(4)}`;
    costAnim.raf = requestAnimationFrame(step);
  };
  costAnim.raf = requestAnimationFrame(step);
}

function ensureAgentCard(name) {
  let card = document.getElementById(`agent-${name}`);
  if (card) return card;
  const idx = AGENT_NAMES.indexOf(name);
  const num = String(idx >= 0 ? idx + 1 : agentsGrid.children.length + 1).padStart(2, '0');
  card = document.createElement('article');
  card.className = 'agent-card pending';
  card.id = `agent-${name}`;
  card.innerHTML = `
    <div class="agent-head">
      <h3 class="agent-name" data-num="${num}">${name}</h3>
      <span class="status-text">pending</span>
    </div>
    <div class="agent-stats">
      <span class="iter">iter 0</span>
      <span class="findings">0 findings</span>
    </div>
    <div class="agent-trace"></div>
  `;
  agentsGrid.appendChild(card);
  return card;
}

function setCardStatus(name, status) {
  const card = ensureAgentCard(name);
  card.classList.remove('pending', 'running', 'done', 'error');
  card.classList.add(status);
  card.querySelector('.status-text').textContent = status;
  updateAgentsMeta();
}

function updateAgentsMeta() {
  const running = agentsGrid.querySelectorAll('.agent-card.running').length;
  const done = agentsGrid.querySelectorAll('.agent-card.done').length;
  const errored = agentsGrid.querySelectorAll('.agent-card.error').length;
  const total = agentsGrid.children.length;
  if (running > 0) agentsMeta.textContent = `${running} running · ${done} done · ${total} total`;
  else if (done + errored === total && total > 0) agentsMeta.textContent = `${done} done · ${errored} errored · ${total} total`;
  else agentsMeta.textContent = `${total} total`;
}

function appendTrace(name, text, cls) {
  const card = ensureAgentCard(name);
  const trace = card.querySelector('.agent-trace');
  const line = document.createElement('div');
  line.className = `trace-line ${cls || ''}`;
  line.textContent = text;
  trace.appendChild(line);
  trace.scrollTop = trace.scrollHeight;
}

function setStat(name, key, value) {
  const card = ensureAgentCard(name);
  card.querySelector(`.${key}`).textContent = value;
}

function nowTs() {
  const d = new Date();
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
}

function feedEntry(agent, message, cls = '') {
  const li = document.createElement('li');
  if (cls) li.className = cls;
  li.innerHTML = `<span class="ts">${nowTs()}</span><span class="agt">${escapeHtml(agent)}</span><span class="msg">${escapeHtml(message)}</span>`;
  feedListEl.insertBefore(li, feedListEl.firstChild);
  feedCounter++;
  feedCountEl.textContent = feedCounter;
  while (feedListEl.children.length > MAX_FEED_ITEMS) {
    feedListEl.removeChild(feedListEl.lastChild);
  }
}

function setPhase(phase) {
  for (const el of phaseEls) {
    const p = el.dataset.phase;
    el.classList.remove('active');
    if (p === phase) el.classList.add('active');
  }
  const order = ['recon', 'specialists', 'stack_specialists', 'reflection', 'aggregating', 'done'];
  const idx = order.indexOf(phase);
  for (let i = 0; i < idx; i++) {
    document.querySelector(`.phase[data-phase="${order[i]}"]`)?.classList.add('complete');
  }
  const labels = { recon: 'Reconnaissance', specialists: 'Specialist agents', stack_specialists: 'Stack-aware agents', reflection: 'Reflection', aggregating: 'Finalizing report', done: 'Complete' };
  if (phase === 'done') setIdle('Complete'); else setLive(labels[phase] || phase);
}

function renderGraph(summary) {
  if (!summary) return;
  const s = summary.stack || {};
  const stackParts = [s.framework, s.backend, s.auth, s.cdn].filter(Boolean);
  gStackEl.textContent = stackParts.length ? stackParts.join(' + ') : 'unknown';
  gStackEl.title = stackParts.join(' + ') + (s.confidence ? ` (confidence: ${s.confidence})` : '');

  const epCount = summary.endpoint_count || 0;
  gEpCountEl.textContent = epCount;
  gEndpointsEl.innerHTML = (summary.endpoints_preview || []).slice(0, 60)
    .map(e => `<li>${escapeHtml(e.method || 'GET')} ${escapeHtml(e.url)}</li>`).join('');

  const secCount = summary.secret_count || 0;
  gSecCountEl.textContent = secCount;
  gSecretsEl.innerHTML = (summary.secrets_preview || []).slice(0, 40)
    .map(x => `<li class="${x.is_public === false ? 'private' : (x.is_public === true ? 'public' : '')}">${escapeHtml(x.type)} · ${escapeHtml(x.preview || '')}</li>`).join('');

  const auth = summary.auth_state || {};
  gAuthEl.textContent = auth.logged_in ? `${auth.email || '?'}` : 'not logged in';
  gAuthEl.title = auth.logged_in ? `logged in as ${auth.email || '?'}` : '';
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = targetInput.value.trim();
  if (!url) return;
  scanBtn.disabled = true;
  scanBtnLabel.textContent = 'Scanning…';
  reset();
  setLive('Initializing');
  statusSection.hidden = false;
  for (const name of AGENT_NAMES) {
    ensureAgentCard(name);
    setCardStatus(name, 'pending');
  }
  try {
    const r = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, tryRegister: tryRegisterEl.checked }),
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      alert(err.error || `Scan request failed (${r.status})`);
      scanBtn.disabled = false; scanBtnLabel.textContent = 'Initiate scan';
      setIdle();
      return;
    }
    const { id } = await r.json();
    streamEvents(id);
  } catch (err) {
    alert(err.message || String(err));
    scanBtn.disabled = false; scanBtnLabel.textContent = 'Initiate scan';
    setIdle();
  }
});

function streamEvents(scanId) {
  const es = new EventSource(`/api/scan/${scanId}/events`);
  es.onmessage = (msg) => {
    let ev;
    try { ev = JSON.parse(msg.data); } catch { return; }

    switch (ev.type) {
      case 'phase':
        setPhase(ev.phase);
        break;

      case 'agent_started':
        setCardStatus(ev.agent, 'running');
        feedEntry(ev.agent, 'started');
        break;

      case 'tool_call':
        setStat(ev.agent, 'iter', `iter ${ev.iteration}`);
        appendTrace(ev.agent, `→ ${ev.tool}(${shortArgs(ev.args)})`, 'tool');
        break;

      case 'tool_result':
        if (ev.error) {
          appendTrace(ev.agent, `  ✗ ${ev.tool} → ${ev.error}`, 'err');
          feedEntry(ev.agent, `${ev.tool}: ${ev.error}`, 'err');
        } else if (ev.status != null) {
          appendTrace(ev.agent, `  ← ${ev.status} · ${ev.timing_ms}ms`, 'tool');
        }
        break;

      case 'think':
        appendTrace(ev.agent, ev.hypothesis, 'think');
        break;

      case 'replan':
        appendTrace(ev.agent, `↻ ${ev.next_attack}${ev.give_up ? ' · stopping' : ''}`, 'replan');
        break;

      case 'finding': {
        const f = ev.finding || {};
        counts[f.severity] = (counts[f.severity] || 0) + 1;
        updateCounts();
        const card = ensureAgentCard(ev.agent);
        const cur = parseInt(card.querySelector('.findings').textContent) || 0;
        setStat(ev.agent, 'findings', `${cur + 1} findings`);
        appendTrace(ev.agent, `★ ${(f.severity || '').toUpperCase()} · ${f.title}`, 'finding');
        feedEntry(ev.agent, `${(f.severity || '').toUpperCase()} · ${f.title}`, 'fnd');
        break;
      }

      case 'agent_completed':
        setCardStatus(ev.agent, 'done');
        feedEntry(ev.agent, 'completed');
        break;

      case 'agent_error':
        setCardStatus(ev.agent, 'error');
        appendTrace(ev.agent, `ERROR: ${ev.error}`, 'err');
        feedEntry(ev.agent, `errored: ${ev.error}`, 'err');
        break;

      case 'cost_update':
        animateCost(ev.total_usd || 0);
        costSubEl.textContent = `${(ev.total_reasoning || 0).toLocaleString()} reasoning tokens`;
        if ((ev.total_usd || 0) > SOFT_WARN_USD) costBlockEl.classList.add('cost-warn');
        break;

      case 'graph_update':
        renderGraph(ev.summary);
        break;

      case 'stack_specialists_firing':
        feedEntry('orchestrator', `stack agents firing: ${(ev.agents || []).join(', ') || 'none'}`);
        break;

      case 'done':
        setPhase('done');
        reportMd.textContent = ev.report || '';
        reportSection.hidden = false;
        downloadLink.href = `/api/scan/${scanId}/report`;
        scanBtn.disabled = false;
        scanBtnLabel.textContent = 'New scan';
        setIdle('Complete');
        // Scroll down to the report once it's painted
        requestAnimationFrame(() => {
          reportSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
        break;

      case 'error':
        alert('Scan failed: ' + ev.error);
        scanBtn.disabled = false;
        scanBtnLabel.textContent = 'Initiate scan';
        setIdle('Error');
        break;

      case 'closed':
        es.close();
        break;
    }
  };
  es.onerror = () => { /* auto-reconnects; closed event handles teardown */ };
}

function shortArgs(args) {
  if (!args) return '';
  if (args.url) return args.url.slice(0, 60);
  if (args.signup_url) return args.signup_url.slice(0, 60);
  if (args.login_url) return args.login_url.slice(0, 60);
  if (args.baseline_url) return `${args.baseline_url.slice(0, 28)} ↔ ${(args.test_url || '').slice(0, 28)}`;
  if (args.base_url) return `${args.base_url} [${args.wordlist}]`;
  return JSON.stringify(args).slice(0, 60);
}

copyBtn.addEventListener('click', async () => {
  await navigator.clipboard.writeText(reportMd.textContent);
  copyBtn.textContent = 'Copied!';
  setTimeout(() => copyBtn.textContent = 'Copy', 1500);
});
