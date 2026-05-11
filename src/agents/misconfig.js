import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runAgent } from './base.js';
import { httpTools } from '../tools/httpProbe.js';
import { fuzzTools } from '../tools/fuzz.js';
import { graphTools } from '../tools/graphTools.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const systemPrompt = await readFile(join(__dirname, '..', 'prompts', 'misconfigSystem.md'), 'utf8');

export async function run({ target, reconSummary, jobId, onEvent }) {
  const userPrompt = `Target: ${target}\n\n## Recon summary\n${reconSummary}\n\nCall read_target_graph first (recon already ran the common-paths inventory — focus on the hits already found, security-header review on the main host, and the embedded-credentials review of the JS bundles in the graph). Many small cheap checks. No iteration cap.`;
  const result = await runAgent({
    name: 'misconfig',
    role: 'misconfig',
    systemPrompt,
    userPrompt,
    jobId,
    tools: [...httpTools, ...fuzzTools, ...graphTools],
    onEvent,
  });
  return result.findings;
}
