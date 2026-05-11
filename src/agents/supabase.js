import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runAgent } from './base.js';
import { httpTools } from '../tools/httpProbe.js';
import { fuzzTools } from '../tools/fuzz.js';
import { graphTools } from '../tools/graphTools.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const systemPrompt = await readFile(join(__dirname, '..', 'prompts', 'supabaseSystem.md'), 'utf8');

export function shouldFire(graph) {
  if (!graph?.secrets) return false;
  return graph.secrets.some(s => s.type === 'SUPABASE_URL' || s.type === 'SUPABASE_ANON');
}

export async function run({ target, reconSummary, jobId, onEvent }) {
  const userPrompt = `Target: ${target}\n\n## Recon summary\n${reconSummary}\n\nRun the Supabase configuration review. Call read_target_graph first to retrieve SUPABASE_URL and SUPABASE_ANON, then verify Row Level Security coverage on each candidate table (using the supabase-tables wordlist), review RPC functions, storage buckets, and auth endpoints. Decode the SUPABASE_ANON JWT and confirm the role claim is "anon" (service_role embedded in a public bundle is a critical config issue). No iteration cap.`;
  const result = await runAgent({
    name: 'supabase',
    role: 'specialist',
    systemPrompt,
    userPrompt,
    jobId,
    tools: [...httpTools, ...fuzzTools, ...graphTools],
    onEvent,
  });
  return result.findings;
}
