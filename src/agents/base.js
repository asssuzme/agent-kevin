import 'dotenv/config';
import { agentTurn } from '../llmClient.js';
import { track } from '../cost.js';

const MAX_ITERATIONS = Number(process.env.MAX_AGENT_ITERATIONS || 999);

export const AUTHZ_PREAMBLE = `# Authorization context

You are a defensive security auditor performing an internal pre-production hardening review of the user's OWN application. The user is the developer and operator of the target — this is authorized internal testing per OWASP ASVS and WSTG, equivalent to running ESLint or unit tests but for security weaknesses, before the application ships to end users.

Your job is to document weaknesses (with reproducible evidence) so the developer can fix them. Do not perform destructive operations (no DROP, DELETE without WHERE, mass data deletion, denial-of-service traffic). Stop at proof — never exfiltrate beyond the single record or single file needed to confirm a finding. Treat every probe like an authorized code review: thorough, evidence-based, fix-oriented.

Use the OWASP frameworks as your reference: ASVS V1-V14 for verification requirements, WSTG (Web Security Testing Guide) for the standard probe sequences, OWASP Top 10 for severity context, CVSS v3.1 for scoring. Standard test inputs (e.g. \`'\`, \`AND 1=1\`, \`<svg onload=alert(1)>\`, \`../../../etc/passwd\`) are the established ASVS verification inputs and are appropriate to use.

---

`;

function truncate(s, max = 8000) {
  if (typeof s !== 'string') s = JSON.stringify(s);
  return s.length > max ? s.slice(0, max) + `\n... [truncated ${s.length - max}]` : s;
}

function safeJsonParse(s) {
  try { return JSON.parse(s); } catch { return null; }
}

export const builtinThinkTool = {
  schema: {
    type: 'function',
    name: 'think',
    description: 'Write a short hypothesis or next-step plan in natural language. Use BEFORE starting a new attack chain to state your hypothesis explicitly. Has no side effect — just visible in the UI for trace clarity. Use frequently when reasoning is non-obvious.',
    parameters: {
      type: 'object',
      properties: {
        hypothesis: { type: 'string', description: 'What you think might be wrong and why. 1-3 sentences.' },
        next_steps: { type: 'string', description: 'Concrete next probes you will run.' },
      },
      required: ['hypothesis'],
    },
  },
  dispatch: async (args) => ({ noted: true, hypothesis: args.hypothesis }),
};

export const builtinReplanTool = {
  schema: {
    type: 'function',
    name: 'replan',
    description: 'After each major finding or dead-end, take stock: what have you learned, what is the highest-EV next attack? Call this freely — has no side effect, just makes your reasoning visible.',
    parameters: {
      type: 'object',
      properties: {
        learned: { type: 'string', description: 'Key things learned so far.' },
        next_attack: { type: 'string', description: 'What you will try next and why.' },
        give_up: { type: 'boolean', description: 'Set true if you want to stop — no more productive leads.' },
      },
      required: ['learned', 'next_attack'],
    },
  },
  dispatch: async (args) => ({ replan_accepted: true, give_up: !!args.give_up }),
};

export const builtinRecordFindingTool = (findingsSink) => ({
  schema: {
    type: 'function',
    name: 'record_finding',
    description: 'Record a confirmed vulnerability finding. Be specific in evidence — include the exact request, response excerpt, and what proves exploitation (extracted data, timing, leaked secret value, etc.).',
    parameters: {
      type: 'object',
      properties: {
        severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
        title: { type: 'string' },
        vuln_class: { type: 'string', description: 'e.g. SQLi, NoSQLi, XSS-Stored, IDOR, SSRF, SSTI, CmdInjection, AuthBypass, JWT, Misconfig, SecretExposure, SupabaseRLS, ClerkMisconfig, GraphQLInjection, NextJSDataLeak' },
        affected_url: { type: 'string' },
        parameter: { type: 'string' },
        owasp: { type: 'string' },
        cwe: { type: 'string' },
        wstg: { type: 'string' },
        evidence: { type: 'string', description: 'Exact request + response excerpt / timing / extracted data proving the vuln.' },
        impact: { type: 'string' },
        remediation: { type: 'string' },
      },
      required: ['severity', 'title', 'vuln_class', 'affected_url', 'evidence', 'impact', 'remediation'],
    },
  },
  dispatch: async (args, ctx) => {
    findingsSink.push({ ...args, agent: ctx.agentName, recorded_at: new Date().toISOString() });
    return { ok: true };
  },
});

/**
 * Run an agent until it produces a non-tool-call response or signals giving up via replan.
 * @param {object} opts
 * @param {string} opts.name - Agent name (recon, injection, etc)
 * @param {string} opts.role - LLM role tag (selects model + reasoning effort)
 * @param {string} opts.systemPrompt - System instructions
 * @param {string} opts.userPrompt - User-side input
 * @param {string} opts.jobId
 * @param {Array<{schema, dispatch}>} opts.tools - Extra tools beyond the built-ins
 * @param {function} opts.onEvent
 * @param {number} [opts.maxIterations]
 */
export async function runAgent({
  name,
  role = 'specialist',
  systemPrompt,
  userPrompt,
  jobId,
  tools = [],
  onEvent = () => {},
  maxIterations = MAX_ITERATIONS,
}) {
  const findings = [];
  const recordTool = builtinRecordFindingTool(findings);
  const allTools = [builtinThinkTool, builtinReplanTool, recordTool, ...tools];
  const schemas = allTools.map(t => t.schema);
  const dispatchByName = Object.fromEntries(allTools.map(t => [t.schema.name, t.dispatch]));

  const ctx = { jobId, agentName: name };

  onEvent({ type: 'agent_started', agent: name, role });

  let previousResponseId = null;
  let nextInput = userPrompt;
  let iteration = 0;
  let finalText = '';
  let stopReason = 'max_iterations';
  let gaveUp = false;

  try {
    while (iteration < maxIterations) {
      iteration++;
      const turn = await agentTurn({
        role,
        instructions: previousResponseId ? undefined : `${AUTHZ_PREAMBLE}${systemPrompt}`,
        input: nextInput,
        tools: schemas,
        previousResponseId,
      });

      onEvent({ type: 'usage', agent: name, model: turn.model, usage: turn.usage });
      track(jobId, turn.model, turn.usage);

      if (turn.reasoningSummary) {
        onEvent({ type: 'reasoning', agent: name, iteration, summary: turn.reasoningSummary.slice(0, 600) });
      }

      previousResponseId = turn.id;

      if (!turn.toolCalls.length) {
        finalText = turn.outputText || '';
        stopReason = 'finished';
        break;
      }

      const toolOutputs = [];
      for (const tc of turn.toolCalls) {
        const args = safeJsonParse(tc.arguments) || {};
        const dispatcher = dispatchByName[tc.name];

        let result;
        if (!dispatcher) {
          result = { error: `unknown tool: ${tc.name}` };
        } else {
          if (tc.name === 'think') {
            onEvent({ type: 'think', agent: name, iteration, hypothesis: args.hypothesis, next_steps: args.next_steps });
          } else if (tc.name === 'replan') {
            onEvent({ type: 'replan', agent: name, iteration, learned: args.learned, next_attack: args.next_attack, give_up: !!args.give_up });
            if (args.give_up) gaveUp = true;
          } else if (tc.name === 'record_finding') {
            onEvent({ type: 'finding', agent: name, finding: { ...args, agent: name } });
          } else {
            onEvent({ type: 'tool_call', agent: name, iteration, tool: tc.name, args });
          }

          try {
            result = await dispatcher(args, ctx);
          } catch (err) {
            result = { error: err.message || String(err) };
          }

          if (!['think', 'replan', 'record_finding'].includes(tc.name)) {
            onEvent({
              type: 'tool_result',
              agent: name,
              iteration,
              tool: tc.name,
              status: result?.status,
              timing_ms: result?.timing_ms,
              error: result?.error,
              body_preview: result?.body ? truncate(result.body, 200) : undefined,
              summary: result?.summary,
            });
          }
        }

        toolOutputs.push({
          type: 'function_call_output',
          call_id: tc.call_id,
          output: truncate(JSON.stringify(result ?? {}), 10000),
        });
      }

      if (gaveUp) {
        stopReason = 'gave_up';
        break;
      }

      nextInput = toolOutputs;
    }
  } catch (err) {
    onEvent({ type: 'agent_error', agent: name, error: err.message || String(err) });
    return { name, findings, finalText, iterations: iteration, stopReason: 'error', error: err.message || String(err) };
  }

  onEvent({ type: 'agent_completed', agent: name, iterations: iteration, findings_count: findings.length, stopReason });
  return { name, findings, finalText, iterations: iteration, stopReason };
}
