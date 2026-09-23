#!/usr/bin/env node
// Build a synthetic DSH session log for CI.
//
// The acceptance harness (`scripts/verify.mjs`) is strongest against a real 20 MiB log, but
// CI has none. This writes a log with the same *shape* — one zstd frame per appended record
// batch, a session header, turns, steps, paired tool calls, usage — so the harness exercises
// frame walking, integrity trees, tamper detection and graph assembly on every push.
//
// It is deliberately labelled: the CI run logs that it used a synthetic log, because a
// passing check against generated data is weaker evidence than one against real data.
import { writeFileSync } from 'node:fs'
import { zstdCompressSync } from 'node:zlib'

const out = process.argv[2]
if (!out) {
  console.error('usage: node scripts/make-synthetic-log.mjs <out.jsonl.zstd>')
  process.exit(2)
}

const frames = []
let time = 1788792998000
const next = () => (time += 137)

/** Some frames carry several records, the way a real append does. */
const push = (...records) => {
  frames.push(zstdCompressSync(Buffer.from(records.map((r) => JSON.stringify(r)).join('\n') + '\n', 'utf8')))
}

const TOOLS = [
  { name: 'pwsh', args: { command: 'Get-ChildItem -Force | Select-Object Name', description: 'list files' }, undecidable: true },
  { name: 'read', args: { file_path: 'C:\\proj\\index.html' } },
  { name: 'write', args: { file_path: 'C:\\proj\\out.html', content: '<!doctype html><title>x</title>' } },
  { name: 'edit', args: { file_path: 'C:\\proj\\out.html', old_string: 'x', new_string: 'y' } },
  { name: 'grep', args: { pattern: 'TODO', path: 'C:\\proj' } },
  { name: 'pwsh', args: { command: 'Remove-Item C:\\proj\\.tmp -Recurse -Force', description: 'clean scratch' }, undecidable: true },
]

let seq = 0
push({
  type: 'session',
  version: 0,
  id: 'session-synthetic-0001',
  createdAt: time,
  cwd: 'C:\\proj',
  delegationDepth: 0,
  agentPreset: 'standard',
})
push({ type: 'permission/preset', seq: seq++, time: next(), data: { preset: 'workspace-write' } })
push({ type: 'sandbox/mode', seq: seq++, time: next(), data: { mode: 'workspace-write' } })
push({ type: 'command/run', seq: seq++, time: next(), data: { commandId: 'cmd-1', name: 'permission', args: ' danger-full-access', source: { kind: 'user' } } })

let callId = 0
for (let turn = 1; turn <= 12; turn++) {
  push({ type: 'turn/start', seq: seq++, time: next(), data: { turn } })
  push({
    type: 'user/message',
    seq: seq++,
    time: next(),
    data: { content: [{ type: 'text', text: `synthetic turn ${turn}` }], role: 'user', id: `msg-${turn}` },
    surfaceOp: 'append',
  })

  for (let step = 1; step <= 3; step++) {
    push({ type: 'step/start', seq: seq++, time: next(), data: { turn, step } })
    push({
      type: 'assistant/message',
      seq: seq++,
      time: next(),
      data: {
        turn,
        step,
        message: {
          role: 'assistant',
          id: `asst-${turn}-${step}`,
          content: [{ type: 'text', text: `working on turn ${turn} step ${step}` }],
          source: { kind: 'model', provider: 'synthetic', model: 'synthetic-model' },
        },
        usage: { inputTokens: 1000 + turn, outputTokens: 120, cacheReadTokens: 9000, reasoningTokens: 40 },
      },
    })

    const tool = TOOLS[(turn + step) % TOOLS.length]
    const id = `call_synth_${callId++}`
    push({ type: 'tool/call', seq: seq++, time: next(), data: { turn, step, callId: id, name: tool.name, arguments: JSON.stringify(tool.args) } })
    push({
      type: 'tool/result',
      seq: seq++,
      time: next(),
      data: {
        turn,
        step,
        message: {
          source: { kind: 'tool', callId: id },
          content: [
            {
              type: 'tool-result',
              toolCallId: id,
              content: [{ type: 'text', text: `synthetic result for ${tool.name}` }],
              isError: false,
            },
          ],
          role: 'user',
          id: `res-${callId}`,
        },
        sourceEventSeqs: [seq - 2],
        surfaceOp: 'append',
      },
    })
    push({ type: 'step/end', seq: seq++, time: next(), data: { turn, step } })
  }

  push({ type: 'turn/end', seq: seq++, time: next(), data: { turn, reason: { kind: 'completed' } } })
}

// One retry and one compaction, so the anomaly paths are covered too.
push({ type: 'llm/retry', seq: seq++, time: next(), data: { retryId: 'r1', turn: 12, step: 3, provider: 'synthetic', retry: 1, maxRetries: 2, failure: { code: 'TRANSPORT', message: 'synthetic' } } })
push({ type: 'compaction/start', seq: seq++, time: next(), data: { compactionId: 'c1', turn: 12 } })

writeFileSync(out, Buffer.concat(frames))
console.log(`wrote ${out}: ${frames.length} frame(s), ${Buffer.concat(frames).length} bytes`)
