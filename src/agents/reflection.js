import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runAgent } from './base.js';
import { httpTools } from '../tools/httpProbe.js';
import { fuzzTools } from '../tools/fuzz.js';
import { graphTools } from '../tools/graphTools.js';
import { authflowTools } from '../tools/authflow.js';
import { getGraph } from '../state/targetGraph.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const systemPrompt = await readFile(join(__dirname, '..', 'prompts', 'reflectionSystem.md'), 'utf8');

export async function run({ target, reconSummary, jobId, allFindings, onEvent }) {
  const graph = getGraph(jobId);
  const findingsSummary = allFindings.length
    ? allFindings.map((f, i) => `${i+1}. [${f.severity}] ${f.title} (${f.vuln_class}) — ${f.affected_url}`).join('\n')
    : '(no findings yet from other agents)';
  const notesSummary = (graph?.notes || []).map(n => `- (${n.agent}) ${n.note}`).join('\n') || '(none)';

  const userPrompt = `Target: ${target}

## Recon summary
${reconSummary}

## Findings reported by other agents (${allFindings.length})
${findingsSummary}

## Agent notes (leads worth following up)
${notesSummary}

Now: call read_target_graph, identify the highest-EV coverage gaps from the work above, and audit 1-2 of them in depth. Report any new weaknesses or severity upgrades you confirm.`;

  const result = await runAgent({
    name: 'reflection',
    role: 'reflection',
    systemPrompt,
    userPrompt,
    jobId,
    tools: [...httpTools, ...fuzzTools, ...graphTools, ...authflowTools],
    onEvent,
  });
  return result.findings;
}
