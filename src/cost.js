const pricing = {
  'gpt-5.5-pro':         { input: 60.0,  cached_input: 30.0, output: 120.0 },
  'gpt-5.5':             { input: 5.0,   cached_input: 2.5,  output: 15.0 },
  'gpt-5.4-pro':         { input: 30.0,  cached_input: 15.0, output: 60.0 },
  'gpt-5.4':             { input: 3.0,   cached_input: 1.5,  output: 12.0 },
  'gpt-5.4-mini':        { input: 0.25,  cached_input: 0.10, output: 1.0 },
  'gpt-5.4-nano':        { input: 0.05,  cached_input: 0.02, output: 0.4 },
  'gpt-5.3-chat-latest': { input: 4.0,   cached_input: 2.0,  output: 16.0 },
  'gpt-5.2-pro':         { input: 25.0,  cached_input: 12.5, output: 50.0 },
  'gpt-5.2':             { input: 2.5,   cached_input: 1.25, output: 10.0 },
  'gpt-5.1':             { input: 1.25,  cached_input: 0.125, output: 10.0 },
  'gpt-5.1-codex-max':   { input: 5.0,   cached_input: 2.5,  output: 20.0 },
  'gpt-5-pro':           { input: 15.0,  cached_input: 7.5,  output: 60.0 },
  'gpt-5':               { input: 1.25,  cached_input: 0.125, output: 10.0 },
  'gpt-5-mini':          { input: 0.25,  cached_input: 0.025, output: 2.0 },
  'gpt-5-nano':          { input: 0.05,  cached_input: 0.005, output: 0.4 },
  'o3':                  { input: 2.0,   cached_input: 0.5,  output: 8.0 },
  'o3-mini':             { input: 1.10,  cached_input: 0.55, output: 4.4 },
  'o4-mini':             { input: 1.10,  cached_input: 0.275, output: 4.4 },
  'o1-pro':              { input: 150.0, cached_input: 150.0, output: 600.0 },
};

function priceFor(model) {
  if (pricing[model]) return pricing[model];
  for (const key of Object.keys(pricing)) {
    if (model.startsWith(key)) return pricing[key];
  }
  return { input: 5.0, cached_input: 2.5, output: 15.0 };
}

const meters = new Map();

export function createMeter(jobId) {
  const m = { totalUsd: 0, byModel: {}, totalInput: 0, totalOutput: 0, totalReasoning: 0 };
  meters.set(jobId, m);
  return m;
}

export function track(jobId, model, usage) {
  const m = meters.get(jobId);
  if (!m) return null;
  const inp = usage.input_tokens || 0;
  const cached = usage.input_tokens_details?.cached_tokens || 0;
  const fresh = Math.max(0, inp - cached);
  const out = usage.output_tokens || 0;
  const reasoning = usage.output_tokens_details?.reasoning_tokens || 0;
  const p = priceFor(model);
  const usd = (fresh * p.input / 1_000_000) + (cached * p.cached_input / 1_000_000) + (out * p.output / 1_000_000);
  const slot = (m.byModel[model] ||= { calls: 0, input: 0, cached: 0, output: 0, reasoning: 0, usd: 0 });
  slot.calls++; slot.input += fresh; slot.cached += cached; slot.output += out; slot.reasoning += reasoning; slot.usd += usd;
  m.totalUsd += usd; m.totalInput += inp; m.totalOutput += out; m.totalReasoning += reasoning;
  return { total_usd: m.totalUsd, delta_usd: usd, model, usage };
}

export function getMeter(jobId) {
  return meters.get(jobId);
}

export function deleteMeter(jobId) {
  meters.delete(jobId);
}
