import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runAgent } from './base.js';
import { httpTools } from '../tools/httpProbe.js';
import { graphTools } from '../tools/graphTools.js';
import { authflowTools } from '../tools/authflow.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const systemPrompt = await readFile(join(__dirname, '..', 'prompts', 'graphqlSystem.md'), 'utf8');

export function shouldFire(graph) {
  if (!graph?.endpoints) return false;
  return graph.endpoints.some(e => /graphql/i.test(e.url));
}

export async function run({ target, reconSummary, jobId, onEvent }) {
  const userPrompt = `Target: ${target}\n\n## Recon summary\n${reconSummary}\n\nRun the GraphQL configuration review. Locate the GraphQL endpoint in the target graph, confirm it, check whether introspection is enabled, then walk through each query and mutation verifying auth coverage and input handling. No iteration cap.`;
  const result = await runAgent({
    name: 'graphql',
    role: 'specialist',
    systemPrompt,
    userPrompt,
    jobId,
    tools: [...httpTools, ...graphTools, ...authflowTools],
    onEvent,
  });
  return result.findings;
}
