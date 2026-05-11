import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runAgent } from './base.js';
import { httpTools } from '../tools/httpProbe.js';
import { fuzzTools } from '../tools/fuzz.js';
import { graphTools } from '../tools/graphTools.js';
import { authflowTools } from '../tools/authflow.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const systemPrompt = await readFile(join(__dirname, '..', 'prompts', 'nextjsSystem.md'), 'utf8');

export function shouldFire(graph) {
  const fw = (graph?.stack?.framework || '').toLowerCase();
  if (fw.includes('next')) return true;
  if (graph?.endpoints?.some(e => /_next\/|__next/i.test(e.url))) return true;
  return false;
}

export async function run({ target, reconSummary, jobId, onEvent }) {
  const userPrompt = `Target: ${target}\n\n## Recon summary\n${reconSummary}\n\nRun the Next.js configuration review. First read_target_graph, then locate the buildId in the root page, then check _next/data for SSR data exposure, _buildManifest for route inventory, /api/* routes for missing auth, image-optimizer URL allowlist coverage, and NextAuth callback URL handling. No iteration cap.`;
  const result = await runAgent({
    name: 'nextjs',
    role: 'specialist',
    systemPrompt,
    userPrompt,
    jobId,
    tools: [...httpTools, ...fuzzTools, ...graphTools, ...authflowTools],
    onEvent,
  });
  return result.findings;
}
