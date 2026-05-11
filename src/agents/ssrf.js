import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runAgent } from './base.js';
import { httpTools } from '../tools/httpProbe.js';
import { graphTools } from '../tools/graphTools.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const systemPrompt = await readFile(join(__dirname, '..', 'prompts', 'ssrfSystem.md'), 'utf8');

export async function run({ target, reconSummary, jobId, onEvent }) {
  const userPrompt = `Target: ${target}\n\n## Recon summary\n${reconSummary}\n\nCall read_target_graph first to review all discovered endpoints. Identify any with url/file/path/proxy/webhook/import parameters — those are the candidates for request-forwarding, XML-parsing, and path-handling review per OWASP ASVS V12-V13. Verify cloud metadata reachability only if the target is likely cloud-hosted. No iteration cap.`;
  const result = await runAgent({
    name: 'ssrf',
    role: 'specialist',
    systemPrompt,
    userPrompt,
    jobId,
    tools: [...httpTools, ...graphTools],
    onEvent,
  });
  return result.findings;
}
