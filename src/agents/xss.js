import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runAgent } from './base.js';
import { httpTools } from '../tools/httpProbe.js';
import { graphTools } from '../tools/graphTools.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const systemPrompt = await readFile(join(__dirname, '..', 'prompts', 'xssSystem.md'), 'utf8');

export async function run({ target, reconSummary, jobId, onEvent }) {
  const userPrompt = `Target: ${target}\n\n## Recon summary\n${reconSummary}\n\nCall read_target_graph first. Walk the OWASP ASVS V5.3 output-encoding review across the discovered user-facing endpoints. Use harmless markers (e.g. vibex"><svg>) to verify rendering context only. No iteration cap.`;
  const result = await runAgent({
    name: 'xss',
    role: 'specialist',
    systemPrompt,
    userPrompt,
    jobId,
    tools: [...httpTools, ...graphTools],
    onEvent,
  });
  return result.findings;
}
