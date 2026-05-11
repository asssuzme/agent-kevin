import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runAgent } from './base.js';
import { httpTools } from '../tools/httpProbe.js';
import { jsBundleTools } from '../tools/jsBundle.js';
import { fuzzTools } from '../tools/fuzz.js';
import { graphTools } from '../tools/graphTools.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const systemPrompt = await readFile(join(__dirname, '..', 'prompts', 'reconSystem.md'), 'utf8');

export async function run({ target, jobId, onEvent }) {
  const userPrompt = `Target: ${target}\n\nMap the security review surface of this application in depth. Extract every JS bundle, identify the stack, populate the target graph with endpoints and configuration data. Use think() and add_note() liberally as you go. Aim for 40-60 tool calls.\n\nWrite your final summary in defensive, fix-oriented language — describe the surface as a developer would describe their own app for hardening, not as an attacker reconnaissance brief.`;
  const result = await runAgent({
    name: 'recon',
    role: 'recon',
    systemPrompt,
    userPrompt,
    jobId,
    tools: [...httpTools, ...jsBundleTools, ...fuzzTools, ...graphTools],
    onEvent,
    maxIterations: 80,
  });
  return result.finalText || '(recon produced no summary text)';
}
