import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { agentTurn } from './llmClient.js';
import { track } from './cost.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const systemPrompt = await readFile(join(__dirname, 'prompts', 'reportTemplate.md'), 'utf8');
const reportsDir = join(__dirname, '..', 'reports');

function stackLine(graph) {
  if (!graph?.stack) return 'Unknown';
  const s = graph.stack;
  const parts = [s.framework, s.backend, s.auth, s.cdn].filter(Boolean);
  return parts.length ? parts.join(' + ') + ` (confidence: ${s.confidence})` : 'Unknown';
}

function secretsAudit(graph) {
  if (!graph?.secrets?.length) return '(none extracted)';
  return graph.secrets.map(s => `- ${s.type}: ${(s.value || '').slice(0, 30)}... (is_public=${s.is_public}, src=${s.source})${s.notes ? '  — ' + s.notes : ''}`).join('\n');
}

export async function render({ target, reconSummary, findings, scanId, graphSnapshot, costSummary }) {
  await mkdir(reportsDir, { recursive: true });

  const stack = stackLine(graphSnapshot);
  const endpointCount = graphSnapshot?.endpoints?.length || 0;
  const secretCount = graphSnapshot?.secrets?.length || 0;

  const userPrompt = `# Inputs

**Target:** ${target}
**Scan ID:** ${scanId}
**Scan date:** ${new Date().toISOString().slice(0, 10)}
**Detected stack:** ${stack}
**Surface mapped:** ${endpointCount} endpoints, ${secretCount} secrets/keys extracted

## Recon summary

${reconSummary || '(none)'}

## Secrets/keys audit (from target graph)

${secretsAudit(graphSnapshot)}

## Raw findings (JSON, ${findings.length} items)

\`\`\`json
${JSON.stringify(findings, null, 2)}
\`\`\`

## Scan cost telemetry

\`\`\`json
${JSON.stringify({
  total_usd: costSummary?.totalUsd?.toFixed?.(4),
  total_input_tokens: costSummary?.totalInput,
  total_output_tokens: costSummary?.totalOutput,
  total_reasoning_tokens: costSummary?.totalReasoning,
  by_model: costSummary?.byModel,
}, null, 2)}
\`\`\`

Now produce the final Markdown report per the format spec. Reminders:
- Fold the detected stack into the executive summary.
- Any secret in the audit with \`is_public=false\` that is NOT already in findings is a **critical** "secret exposure" finding — add it.
- Sort findings critical → high → medium → low → info.
- End with a one-line scan-cost note.
Output the Markdown only — no preamble, no code fences around the whole report.`;

  const turn = await agentTurn({
    role: 'aggregator',
    instructions: systemPrompt,
    input: userPrompt,
  });
  track(scanId, turn.model, turn.usage);

  const report = turn.outputText || '# Report generation failed\n\nNo content returned.';
  const reportPath = join(reportsDir, `${scanId}.md`);
  await writeFile(reportPath, report, 'utf8');
  return { report, reportPath };
}
