// Tests for the integrity layer, effect attribution and execution graph.
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, hash } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { zstdCompressSync } from 'node:zlib'

import { MerkleTree, buildManifest, extractRecordMeta, hashLeaf, hashNode, signManifest, verifyManifest, verifyManifestSignature } from '../lib/merkle.js'
import { buildVersionChains, effectsOf, resolvePath, summarizeEffects } from '../lib/effects.js'
import { buildGraph } from '../lib/graph.js'
import { readLedger } from '../lib/index.js'

const sha = (s) => hash('sha256', Buffer.from(s), 'buffer')

// ── Merkle: against the RFC 6962 definition, not against itself ────────────

test('roots match the RFC 6962 recursive definition', () => {
  const leaves = ['a', 'b', 'c', 'd', 'e'].map(sha)
  const L = leaves.map(hashLeaf)
  const tree = MerkleTree.fromHashes(L)

  // MTH([d0]) = SHA-256(0x00 || d0)
  assert.deepEqual(MerkleTree.fromHashes([L[0]]).root, hashLeaf(sha('a')))
  // MTH(D[0:2]) = SHA-256(0x01 || MTH([d0]) || MTH([d1]))
  assert.deepEqual(MerkleTree.fromHashes(L.slice(0, 2)).root, hashNode(L[0], L[1]))
  // MTH(D[0:3]) = SHA-256(0x01 || MTH(D[0:2]) || MTH([d2]))  — k = 2
  const mth01 = hashNode(L[0], L[1])
  assert.deepEqual(MerkleTree.fromHashes(L.slice(0, 3)).root, hashNode(mth01, L[2]))
  // MTH(D[0:5]) = SHA-256(0x01 || MTH(D[0:4]) || MTH([d4]))  — k = 4
  const mth0123 = hashNode(hashNode(L[0], L[1]), hashNode(L[2], L[3]))
  assert.deepEqual(tree.root, hashNode(mth0123, L[4]))
  // MTH([]) = SHA-256()
  assert.deepEqual(MerkleTree.fromHashes([]).root, sha(''))
})

test('inclusion proofs verify for every leaf at every awkward tree size', () => {
  for (let size = 1; size <= 33; size++) {
    const data = Array.from({ length: size }, (_, i) => Buffer.from(`leaf-${i}`))
    const tree = MerkleTree.fromLeaves(data)
    for (let i = 0; i < size; i++) {
      const proof = tree.prove(i)
      assert.ok(
        MerkleTree.verifyLeaf(proof, data[i], tree.root),
        `size=${size} leaf=${i} should verify`,
      )
      // A proof for the wrong leaf content must fail.
      assert.ok(!MerkleTree.verifyLeaf(proof, Buffer.from(`other-${i}`), tree.root))
      // A proof replayed against another leaf's slot must fail.
      if (i + 1 < size) assert.ok(!MerkleTree.verifyLeaf(tree.prove(i + 1), data[i], tree.root))
    }
  }
})

test('a leaf hash cannot be forged from an internal node', () => {
  // Domain separation: without the 0x00/0x01 prefixes, hashing two children and
  // presenting the result as a leaf would let an attacker prove a node is a leaf.
  const a = hashLeaf(Buffer.from('a'))
  const b = hashLeaf(Buffer.from('b'))
  const node = hashNode(a, b)
  const tree = MerkleTree.fromLeaves([Buffer.from('x'), Buffer.from('y')])
  assert.ok(!MerkleTree.verify({ leaf: 0, size: 2, path: [{ hash: b.toString('hex'), side: 'right' }] }, node, tree.root))
})

test('changing one byte of one leaf changes the root', () => {
  const data = Array.from({ length: 7 }, (_, i) => Buffer.from(`payload-${i}`))
  const root = MerkleTree.fromLeaves(data).root
  for (let i = 0; i < data.length; i++) {
    const tampered = [...data]
    tampered[i] = Buffer.from(`payload-${i} `) // one extra byte
    assert.notDeepEqual(MerkleTree.fromLeaves(tampered).root, root, `leaf ${i}`)
  }
})

// ── effects ────────────────────────────────────────────────────────────────

const call = (name, args, over = {}) => ({
  callId: over.callId ?? `c${Math.random().toString(16).slice(2)}`,
  name,
  arguments: args,
  rawArguments: JSON.stringify(args),
  turn: over.turn ?? 1,
  step: over.step ?? 1,
  seq: over.seq ?? 10,
  time: over.time ?? 1000,
  frameIndex: 0,
  frameStart: 0,
})

test('effects record fidelity honestly per tool', () => {
  const write = effectsOf(call('write', { file_path: 'a/b.txt', content: 'hello' }, { seq: 1 }), 'C:\\proj')[0]
  assert.equal(write.kind, 'write')
  assert.equal(write.fidelity, 'exact')
  assert.equal(write.path, 'C:\\proj\\a\\b.txt')
  assert.equal(write.contentHash, createHash('sha256').update('hello').digest('hex'))
  assert.equal(write.undecidable, false)

  const edit = effectsOf(call('edit', { file_path: 'a/b.txt', old_string: 'x', new_string: 'yy' }, { seq: 2 }), 'C:\\proj')[0]
  assert.equal(edit.kind, 'edit')
  // An edit only carries the replaced fragment, never the whole file.
  assert.equal(edit.fidelity, 'partial')
  assert.equal(edit.undecidable, false)

  const shell = effectsOf(call('pwsh', { command: 'Remove-Item -Recurse -Force .' }, { seq: 3 }), 'C:\\proj')[0]
  assert.equal(shell.kind, 'shell')
  assert.equal(shell.fidelity, 'undecidable')
  assert.equal(shell.undecidable, true)
  assert.match(shell.source, /Remove-Item/)

  const unknown = effectsOf(call('brand_new_tool', { whatever: 1 }, { seq: 4 }), 'C:\\proj')[0]
  assert.equal(unknown.kind, 'unknown')
  assert.equal(unknown.undecidable, true)
})

test('resolvePath handles absolute, relative and forward-slash paths', () => {
  assert.equal(resolvePath('a\\b.txt', 'C:\\proj'), 'C:\\proj\\a\\b.txt')
  assert.equal(resolvePath('a/b.txt', 'C:\\proj'), 'C:\\proj\\a\\b.txt')
  assert.equal(resolvePath('C:/other/x.txt', 'C:\\proj'), 'C:\\other\\x.txt')
  assert.equal(resolvePath('"quoted.txt"', 'C:\\proj'), 'C:\\proj\\quoted.txt')
})

test('version chains classify created vs preexisting and flag shell contamination', () => {
  const effects = [
    effectsOf(call('write', { file_path: 'new.txt', content: 'a' }, { seq: 1 }), 'C:\\p')[0],
    effectsOf(call('edit', { file_path: 'new.txt', old_string: 'a', new_string: 'b' }, { seq: 2 }), 'C:\\p')[0],
    effectsOf(call('read', { file_path: 'old.txt' }, { seq: 3 }), 'C:\\p')[0],
    // A shell command between two versions of a path leaves that path open to
    // effects the log cannot reconstruct.
    effectsOf(call('pwsh', { command: 'echo hi > new.txt' }, { seq: 4 }), 'C:\\p')[0],
    effectsOf(call('edit', { file_path: 'new.txt', old_string: 'b', new_string: 'c' }, { seq: 5 }), 'C:\\p')[0],
    effectsOf(call('read', { file_path: 'old.txt' }, { seq: 6 }), 'C:\\p')[0],
    // This path is only touched after the last shell command, so it stays clean.
    effectsOf(call('read', { file_path: 'clean.txt' }, { seq: 7 }), 'C:\\p')[0],
    effectsOf(call('write', { file_path: 'clean.txt', content: 'z' }, { seq: 8 }), 'C:\\p')[0],
  ]
  const chains = buildVersionChains(effects)
  const created = chains.get('C:\\p\\new.txt')
  const opened = chains.get('C:\\p\\old.txt')
  const clean = chains.get('C:\\p\\clean.txt')

  assert.equal(created.created, true)
  assert.equal(created.steps.length, 3)
  // The shell at seq 4 sits inside new.txt's window [1,5].
  assert.equal(created.contaminated, true)
  assert.equal(created.shellsInWindow, 1)

  // old.txt is only read, but the shell falls between its two reads [3,6].
  assert.equal(opened.preexisting, true)
  assert.equal(opened.contaminated, true)

  assert.equal(clean.created, false)
  assert.equal(clean.steps.length, 2)
  assert.equal(clean.contaminated, false)
  assert.equal(clean.shellsInWindow, 0)
  assert.equal(clean.lastExactHash, createHash('sha256').update('z').digest('hex'))
})

// ── graph ──────────────────────────────────────────────────────────────────

/** Build records the way the tailer would hand them over. */
const rec = (value, frameIndex = 0) => ({ value, frameIndex, frameStart: frameIndex * 100 })

test('graph reconstructs turns, steps, tool pairing and usage', () => {
  const records = [
    rec({ type: 'session', id: 's1', createdAt: 1, cwd: 'C:\\proj', agentPreset: 'standard' }),
    rec({ type: 'permission/preset', seq: 0, time: 1, data: { preset: 'workspace-write' } }),
    rec({ type: 'turn/start', seq: 1, time: 100, data: { turn: 1 } }),
    rec({ type: 'step/start', seq: 2, time: 110, data: { turn: 1, step: 1 } }),
    rec({
      type: 'assistant/message',
      seq: 3,
      time: 120,
      data: {
        turn: 1,
        step: 1,
        message: { id: 'm1', role: 'assistant', content: [{ type: 'text', text: 'working on it' }], source: { model: 'test-model' } },
        usage: { inputTokens: 100, outputTokens: 20, cacheReadTokens: 300, reasoningTokens: 5 },
      },
    }),
    rec({ type: 'tool/call', seq: 4, time: 130, data: { turn: 1, step: 1, callId: 'k1', name: 'write', arguments: '{"file_path":"x.txt","content":"hi"}' } }),
    rec({
      type: 'tool/result',
      seq: 5,
      time: 180,
      data: { turn: 1, step: 1, message: { source: { kind: 'tool', callId: 'k1' }, content: [{ type: 'tool-result', toolCallId: 'k1', content: [{ type: 'text', text: 'ok' }], isError: false }] } },
    }),
    rec({ type: 'tool/call', seq: 6, time: 190, data: { turn: 1, step: 1, callId: 'k2', name: 'edit', arguments: '{"file_path":"x.txt","old_string":"a","new_string":"b"}' } }),
    rec({
      type: 'tool/result',
      seq: 7,
      time: 200,
      data: { turn: 1, step: 1, message: { source: { kind: 'tool', callId: 'k2' }, content: [{ type: 'tool-result', toolCallId: 'k2', content: [{ type: 'text', text: 'old_string was not found' }], isError: true }] } },
    }),
    rec({ type: 'step/end', seq: 8, time: 210, data: { turn: 1, step: 1 } }),
    rec({ type: 'turn/end', seq: 9, time: 220, data: { turn: 1, reason: { kind: 'completed' } } }),
    rec({ type: 'llm/retry', seq: 10, time: 230, data: { retryId: 'r1', turn: 1, step: 2, retry: 1, maxRetries: 2, failure: { code: 'TRANSPORT', message: 'boom' } } }),
  ]
  const graph = buildGraph(records)
  assert.equal(graph.session.id, 's1')
  assert.equal(graph.session.cwd, 'C:\\proj')
  assert.equal(graph.governance.permissionPreset, 'workspace-write')
  assert.equal(graph.turns.length, 1)
  const turn = graph.turns[0]
  assert.equal(turn.durationMs, 120)
  assert.equal(turn.endReason, 'completed')
  assert.equal(turn.unterminated, false)
  assert.equal(turn.steps.length, 1)
  assert.equal(turn.steps[0].durationMs, 100)
  assert.equal(graph.stats.toolCalls, 2)
  assert.equal(graph.stats.paired, 2)
  assert.equal(graph.usage.inputTokens, 100)
  assert.equal(graph.usage.cacheReadTokens, 300)
  assert.equal(graph.usage.messages, 1)
  assert.deepEqual(graph.assistantTexts, [{ turn: 1, step: 1, text: 'working on it', id: 'm1' }])

  // Effects are attached to the call, and the failed edit is an anomaly.
  const write = graph.calls.find((c) => c.call.callId === 'k1')
  assert.equal(write.effects[0].kind, 'write')
  assert.equal(write.durationMs, 50)
  assert.equal(write.result.isError, false)
  const edit = graph.calls.find((c) => c.call.callId === 'k2')
  assert.equal(edit.result.isError, true)
  assert.equal(turn.errors, 1)
  assert.ok(graph.anomalies.some((a) => a.kind === 'tool-error'))
  assert.ok(graph.anomalies.some((a) => a.kind === 'llm-retry' && a.data.code === 'TRANSPORT'))
})

test('graph reports unpaired tool calls and duplicate usage', () => {
  const records = [
    rec({ type: 'turn/start', seq: 1, time: 1, data: { turn: 1 } }),
    rec({
      type: 'assistant/message',
      seq: 2,
      time: 2,
      data: { turn: 1, step: 1, message: { id: 'dup', content: [] }, usage: { inputTokens: 10, outputTokens: 1 } },
    }),
    // Same message id again (a retry re-emit) must not double-count usage.
    rec({
      type: 'assistant/message',
      seq: 3,
      time: 3,
      data: { turn: 1, step: 1, message: { id: 'dup', content: [] }, usage: { inputTokens: 10, outputTokens: 1 } },
    }),
    rec({ type: 'tool/call', seq: 4, time: 4, data: { turn: 1, step: 1, callId: 'lonely', name: 'read', arguments: '{"file_path":"p"}' } }),
    rec({ type: 'tool/result', seq: 5, time: 5, data: { message: { source: { callId: 'ghost' }, content: [] } } }),
  ]
  const graph = buildGraph(records)
  assert.equal(graph.usage.inputTokens, 10)
  assert.equal(graph.stats.paired, 0)
  assert.ok(graph.anomalies.some((a) => a.kind === 'unpaired-tool-call'))
  assert.ok(graph.anomalies.some((a) => a.kind === 'orphan-tool-result'))
})

test('extractRecordMeta reads seq without parsing the whole record', () => {
  assert.deepEqual(extractRecordMeta('{"type":"tool/call","seq":113,"time":1}'), { type: 'tool/call', seq: 113, sessionId: undefined })
  assert.equal(extractRecordMeta('{"type":"reasoning-chunks","seq0":14,"time0":1,"data":{"seq":99}}').seq, 14)
  assert.equal(extractRecordMeta('{"type":"session","version":0,"id":"s-1","createdAt":1}').sessionId, 's-1')
  assert.equal(extractRecordMeta('not json').type, undefined)
})

// ── end to end on a real file ──────────────────────────────────────────────

async function writeSyntheticLog(path, records) {
  const frames = records.map((r) => zstdCompressSync(Buffer.from(JSON.stringify(r) + '\n', 'utf8')))
  await writeFile(path, Buffer.concat(frames))
}

test('manifest verifies a clean log and rejects every kind of tampering', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-ledger-merkle-'))
  const path = join(dir, 'session.jsonl.zstd')
  try {
    const records = [
      { type: 'session', version: 0, id: 'sess-1', createdAt: 1, cwd: 'C:\\p' },
      ...Array.from({ length: 30 }, (_, i) => ({ type: 'tool/call', seq: i, time: 1000 + i, data: { turn: 1, step: 1, callId: `c${i}`, name: 'read', arguments: `{"file_path":"f${i}.txt"}` } })),
    ]
    await writeSyntheticLog(path, records)

    const { manifest, records: leaves } = await buildManifest(path)
    assert.equal(manifest.frames, 31)
    assert.equal(manifest.records, 31)
    assert.equal(manifest.sessionId, 'sess-1')
    assert.equal(leaves.length, 31)

    const clean = await verifyManifest(path, manifest)
    assert.equal(clean.ok, true)

    // 1. A flipped byte inside a frame: same length, different content, so the
    //    frame root is what catches it.
    const original = await (await import('node:fs/promises')).readFile(path)
    const flipped = Buffer.from(original)
    flipped[flipped.length - 40] ^= 0x01
    await writeFile(path, flipped)
    const byteFlipped = await verifyManifest(path, manifest)
    assert.equal(byteFlipped.ok, false)
    assert.equal(byteFlipped.mismatch, 'frameRoot')

    // 2. A truncated log: shorter, so the length check fires first.
    await writeFile(path, original.subarray(0, original.length - 5))
    const truncated = await verifyManifest(path, manifest)
    assert.equal(truncated.ok, false)
    assert.equal(truncated.mismatch, 'bytes')

    // 3. An appended frame: no existing byte changed, but the log grew.
    const extra = zstdCompressSync(Buffer.from(JSON.stringify({ type: 'tool/call', seq: 999, time: 1, data: {} }) + '\n'))
    await writeFile(path, Buffer.concat([original, extra]))
    const appended = await verifyManifest(path, manifest)
    assert.equal(appended.ok, false)
    assert.equal(appended.mismatch, 'bytes')

    // 4. Same length, reordered frames: length and count both match, so only the
    //    Merkle root can detect it. This is the case a checksum-the-file approach
    //    with a length field would miss.
    const frameA = zstdCompressSync(Buffer.from(JSON.stringify({ type: 'tool/call', seq: 1, time: 1, data: { callId: 'a' } }) + '\n'))
    const frameB = zstdCompressSync(Buffer.from(JSON.stringify({ type: 'tool/call', seq: 2, time: 2, data: { callId: 'bb' } }) + '\n'))
    const two = Buffer.concat([frameA, frameB])
    const twoPath = join(dir, 'two.jsonl.zstd')
    await writeFile(twoPath, two)
    const twoManifest = (await buildManifest(twoPath)).manifest
    // Swap the two frames: the file keeps the same length and the same frame count.
    const swapped = Buffer.concat([frameB, frameA])
    assert.equal(swapped.length, two.length)
    await writeFile(twoPath, swapped)
    const reordered = await verifyManifest(twoPath, twoManifest)
    assert.equal(reordered.ok, false)
    assert.equal(reordered.mismatch, 'frameRoot')

    // 5. Restored bytes verify again.
    await writeFile(path, original)
    assert.equal((await verifyManifest(path, manifest)).ok, true)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('a manifest can be signed and a tampered manifest is detected', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  const base = {
    version: 1,
    algorithm: 'sha256/rfc6962',
    file: 'session.jsonl.zstd',
    bytes: 1,
    frames: 2,
    records: 3,
    frameRoot: 'aa'.repeat(32),
    recordRoot: 'bb'.repeat(32),
    generatedAt: 1234,
  }
  const signed = signManifest(base, pem)
  assert.equal(verifyManifestSignature(signed), true)
  assert.ok(publicKey)

  // Any covered field change invalidates the signature.
  const tampered = { ...signed, records: 4 }
  assert.equal(verifyManifestSignature(tampered), false)
  const rootSwap = { ...signed, recordRoot: 'cc'.repeat(32) }
  assert.equal(verifyManifestSignature(rootSwap), false)
  // Dropping the signature material is not a pass.
  assert.equal(verifyManifestSignature({ ...signed, signature: undefined }), false)
})

test('selective disclosure: one record is provable without revealing the rest', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-ledger-disclose-'))
  const path = join(dir, 'session.jsonl.zstd')
  try {
    const records = Array.from({ length: 40 }, (_, i) => ({
      type: 'tool/call',
      seq: i,
      time: 1000 + i,
      data: { turn: 1, step: 1, callId: `c${i}`, name: 'write', arguments: `{"file_path":"secret/f${i}.txt","content":"data-${i}"}` },
    }))
    await writeSyntheticLog(path, records)
    const { manifest, recordTree, records: leaves } = await buildManifest(path)

    // Publish: the root, the record count, and a proof for record 17 only.
    const proof = recordTree.prove(17)
    const revealed = await (await import('node:fs/promises')).readFile(path)
    void revealed
    const line = Buffer.from(JSON.stringify(records[17]), 'utf8')
    assert.equal(hashLeaf(line).toString('hex'), leaves[17].hash)
    assert.ok(MerkleTree.verify(proof, hashLeaf(line), Buffer.from(manifest.recordRoot, 'hex')))

    // The verifier never sees the other 39 records, yet can check the root.
    const withheld = leaves.filter((_, i) => i !== 17)
    assert.equal(withheld.length, 39)
    assert.ok(!MerkleTree.verify(proof, hashLeaf(Buffer.from('{"forged":true}')), Buffer.from(manifest.recordRoot, 'hex')))
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('readLedger produces one integrity pass and a consistent snapshot', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-ledger-read-'))
  const path = join(dir, 'session.jsonl.zstd')
  try {
    await writeSyntheticLog(path, [
      { type: 'session', version: 0, id: 'e2e', createdAt: 1, cwd: 'C:\\proj' },
      { type: 'turn/start', seq: 1, time: 1, data: { turn: 1 } },
      { type: 'step/start', seq: 2, time: 2, data: { turn: 1, step: 1 } },
      { type: 'tool/call', seq: 3, time: 3, data: { turn: 1, step: 1, callId: 'w1', name: 'write', arguments: '{"file_path":"out.txt","content":"hello"}' } },
      { type: 'tool/result', seq: 4, time: 4, data: { turn: 1, step: 1, message: { source: { callId: 'w1' }, content: [{ type: 'tool-result', toolCallId: 'w1', content: [{ type: 'text', text: 'done' }], isError: false }] } } },
      { type: 'step/end', seq: 5, time: 5, data: { turn: 1, step: 1 } },
      { type: 'turn/end', seq: 6, time: 6, data: { turn: 1, reason: { kind: 'completed' } } },
    ])
    const snap = await readLedger(path)
    assert.equal(snap.ingest.frames, 7)
    assert.equal(snap.ingest.records, 7)
    assert.equal(snap.ingest.diagnostics.length, 0)
    assert.equal(snap.integrity.frames, 7)
    assert.equal(snap.graph.session.id, 'e2e')
    assert.equal(snap.effectSummary.write, 1)
    assert.equal(snap.chains.get('C:\\proj\\out.txt').created, true)
    assert.match(snap.integrity.frameRoot, /^[0-9a-f]{64}$/)
    assert.equal((await verifyManifest(path, (await buildManifest(path)).manifest)).ok, true)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
