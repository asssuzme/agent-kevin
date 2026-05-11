import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runAgent } from './base.js';
import { httpTools } from '../tools/httpProbe.js';
import { graphTools } from '../tools/graphTools.js';
import { authflowTools } from '../tools/authflow.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const systemPrompt = await readFile(join(__dirname, '..', 'prompts', 'clerkSystem.md'), 'utf8');

export function shouldFire(graph) {
  if (!graph?.secrets) return false;
  return graph.secrets.some(s => s.type === 'CLERK_PUB_KEY' || s.type === 'CLERK_FRONTEND');
}

export async function run({ target, reconSummary, jobId, tryRegister, onEvent }) {
  const userPrompt = `Target: ${target}\n\n## Recon summary\n${reconSummary}\n\n${tryRegister ? 'Authenticated review ENABLED — register an account via the Clerk signup flow, then set_auth_state so subsequent auditors can continue.' : 'Authenticated review OFF — focus on the Clerk frontend configuration audit + verifying the customer-side endpoints enforce auth correctly.'} Call read_target_graph first. No iteration cap.`;
  const result = await runAgent({
    name: 'clerk',
    role: 'specialist',
    systemPrompt,
    userPrompt,
    jobId,
    tools: [...httpTools, ...graphTools, ...authflowTools],
    onEvent,
  });
  return result.findings;
}
