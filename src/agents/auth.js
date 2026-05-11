import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runAgent } from './base.js';
import { httpTools } from '../tools/httpProbe.js';
import { graphTools } from '../tools/graphTools.js';
import { authflowTools } from '../tools/authflow.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const systemPrompt = await readFile(join(__dirname, '..', 'prompts', 'authSystem.md'), 'utf8');

export async function run({ target, reconSummary, jobId, tryRegister, onEvent }) {
  const userPrompt = `Target: ${target}\n\n## Recon summary\n${reconSummary}\n\nCall read_target_graph first. ${tryRegister ? 'Authenticated review IS ENABLED — exercise the registration and login flows via register_account / login_account to obtain a valid session, then audit the authenticated portions of the surface. After successful login, call set_auth_state so other auditors can continue against authenticated routes.' : 'Authenticated review is OFF for this run — focus on the unauthenticated authentication boundary checks.'} No iteration cap.`;
  const result = await runAgent({
    name: 'auth',
    role: 'specialist',
    systemPrompt,
    userPrompt,
    jobId,
    tools: [...httpTools, ...graphTools, ...authflowTools],
    onEvent,
  });
  return result.findings;
}
