import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runAgent } from './base.js';
import { httpTools } from '../tools/httpProbe.js';
import { graphTools } from '../tools/graphTools.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const systemPrompt = await readFile(join(__dirname, '..', 'prompts', 'injectionSystem.md'), 'utf8');

export async function run({ target, reconSummary, jobId, onEvent }) {
  const userPrompt = `Target: ${target}\n\n## Recon summary\n${reconSummary}\n\nCall read_target_graph first to review the discovered endpoints and configuration. Then walk the OWASP ASVS V5 input-handling review chain for each candidate parameter. Document each weakness with concrete reproducible evidence. Never run destructive statements. No iteration cap — continue auditing until no productive leads remain.`;
  const result = await runAgent({
    name: 'injection',
    role: 'specialist',
    systemPrompt,
    userPrompt,
    jobId,
    tools: [...httpTools, ...graphTools],
    onEvent,
  });
  return result.findings;
}
