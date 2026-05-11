import OpenAI from 'openai';
import 'dotenv/config';

const useOpenAIDirect = !!process.env.OPENAI_API_KEY;

const baseURL = useOpenAIDirect
  ? (process.env.OPENAI_BASE_URL || 'https://api.openai.com/v1')
  : process.env.AZURE_OPENAI_ENDPOINT;

const apiKey = useOpenAIDirect ? process.env.OPENAI_API_KEY : process.env.AZURE_OPENAI_KEY;

if (!baseURL || !apiKey) {
  throw new Error('Missing LLM credentials. Set OPENAI_API_KEY (preferred) or AZURE_OPENAI_ENDPOINT+KEY in env.');
}

const fallbackModel = useOpenAIDirect ? 'gpt-5.5' : (process.env.AZURE_OPENAI_DEPLOYMENT || 'gpt-5.1');

export const client = new OpenAI({ baseURL, apiKey });

export function modelFor(role) {
  const map = {
    recon: process.env.MODEL_RECON,
    specialist: process.env.MODEL_SPECIALIST,
    misconfig: process.env.MODEL_MISCONFIG,
    aggregator: process.env.MODEL_AGGREGATOR,
    reflection: process.env.MODEL_SPECIALIST,
  };
  return map[role] || fallbackModel;
}

export function reasoningEffortFor(role) {
  const map = {
    recon: process.env.REASONING_EFFORT_RECON || 'medium',
    specialist: process.env.REASONING_EFFORT_SPECIALIST || 'high',
    misconfig: process.env.REASONING_EFFORT_MISCONFIG || 'low',
    aggregator: process.env.REASONING_EFFORT_AGGREGATOR || 'low',
    reflection: process.env.REASONING_EFFORT_REFLECTION || 'high',
  };
  return map[role] || 'medium';
}

/**
 * One agent turn using the Responses API.
 * Returns: { id, outputText, toolCalls, reasoningSummary, usage, raw }
 */
export async function agentTurn({ role, instructions, input, tools, previousResponseId, maxRetries = 3 }) {
  let attempt = 0;
  let lastErr;
  const model = modelFor(role);
  const effort = reasoningEffortFor(role);

  while (attempt < maxRetries) {
    try {
      const params = { model };
      if (previousResponseId) params.previous_response_id = previousResponseId;
      if (instructions && !previousResponseId) params.instructions = instructions;
      params.input = input;
      if (tools && tools.length) params.tools = tools;
      if (effort && effort !== 'none') params.reasoning = { effort };

      const resp = await client.responses.create(params);

      const toolCalls = (resp.output || [])
        .filter(o => o.type === 'function_call')
        .map(o => ({ call_id: o.call_id, name: o.name, arguments: o.arguments }));

      const reasoningSummary = (resp.output || [])
        .filter(o => o.type === 'reasoning')
        .flatMap(o => (o.summary || []).map(s => s.text || s))
        .join('\n');

      return {
        id: resp.id,
        outputText: resp.output_text || '',
        toolCalls,
        reasoningSummary,
        usage: resp.usage || {},
        model,
        raw: resp,
      };
    } catch (err) {
      lastErr = err;
      const status = err?.status || err?.response?.status;
      const code = err?.code;
      if (status === 429 || (status >= 500 && status < 600) || code === 'ETIMEDOUT' || code === 'ECONNRESET') {
        const backoff = 800 * Math.pow(2, attempt) + Math.random() * 400;
        await new Promise(r => setTimeout(r, backoff));
        attempt++;
        continue;
      }
      throw err;
    }
  }
  throw lastErr;
}
