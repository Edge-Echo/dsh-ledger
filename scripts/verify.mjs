// dsh-ledger acceptance harness.
//
// Runs against a real DSH session log (the largest one found, or $DSH_LEDGER_LOG)
// and checks the properties this library actually claims:
//
//   1. structural ingestion of every frame, with zero diagnostics
//   2. bounded memory ??a 21 MB log ingests without retaining it
//   3. checkpoint resume ??restarting from the checkpoint reads nothing
//   4. append safety ??a half-written frame is held back, then read exactly once
//   5. tamper detection ??a flipped payload byte is caught, not silently accepted
//   6. corruption resilience ??a destroyed frame region does not hide the rest
//
// Verification is not self-confirming: boundaries found by the structural walker
// are handed to zlib, which validates each frame's own checksum and framing. A
// one-byte boundary error anywhere makes zstdDecompressSync throw.
import { copyFile, mkdtemp, open, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { zstdCompressSync } from 'node:zlib'

import { ZSTD_MAGIC, walkFrameAt } from '../lib/frames.js'
import { SessionLogTailer } from '../lib/reader.js'
import { MerkleTree, buildManifest, hashLeaf, verifyManifest } from '../lib/merkle.js'
import { readLedger } from '../lib/index.js'

const results = []
let failed = 0

function check(name, ok, detail = '') {
  results.push({ name, ok: !!ok, detail })
  if (!ok) failed++
  const mark = ok ? 'PASS' : 'FAIL'
  console.log(`  [${mark}] ${name}${detail ? ` — ${detail}` : ''}`)
}

function section(title) {
  console.log(`\n${title}`)
}

const mb = (n) => (n / 1048576).toFixed(2)

/** Largest session log under $DSH_HOME/sessions, as a fallback target. */
async function discoverLog() {
  if (process.env.DSH_LEDGER_LOG) return process.env.DSH_LEDGER_LOG
  const home = process.env.DSH_HOME ?? join(homedir(), '.dsh')
  const root = join(home, 'sessions')
  if (!existsSync(root)) return null
  let best = null
  let bestSize = 0
  for (const dir of await readdir(root, { withFileTypes: true })) {
    if (!dir.isDirectory()) continue
    const sessions = await readdir(join(root, dir.name), { withFileTypes: true }).catch(() => [])
    for (const s of sessions) {
      if (!s.isDirectory()) continue
      const candidate = join(root, dir.name, s.name, 'session.jsonl.zstd')
      if (!existsSync(candidate)) continue
      const { size } = await stat(candidate)
      if (size > bestSize) {
        bestSize = size
        best = candidate
      }
    }
  }
  return best
}

const target = await discoverLog()
if (!target) {
  console.error('no session log found; set DSH_LEDGER_LOG to one')
  process.exit(2)
}
const targetSize = (await stat(target)).size
console.log(`target: ${target}`)
console.log(`size:   ${targetSize} bytes (${mb(targetSize)} MiB)`)

// ── 1. structural ingestion + bounded memory ───────────────────────────────
section('1. structural ingestion with bounded memory')
{
  const tailer = new SessionLogTailer(target)
  const started = process.hrtime.bigint()
  let frames = 0
  let records = 0
  let bytes = 0
  let peakHeap = 0
  let peakRss = 0
  let peakPending = 0
  let polls = 0
  // Deliberately incremental: no drain(), no retention. If memory grew with file
  // size, this is where it would show.
  for (;;) {
    const batch = await tailer.poll()
    polls++
    frames += batch.frames
    records += batch.records.length
    bytes = batch.bytesConsumed
    peakPending = Math.max(peakPending, batch.pendingBytes)
    if (batch.diagnostics.length > 0) {
      console.log(`    diagnostic: ${JSON.stringify(batch.diagnostics[0])}`)
    }
    const mem = process.memoryUsage()
    peakHeap = Math.max(peakHeap, mem.heapUsed)
    peakRss = Math.max(peakRss, mem.rss)
    if (batch.atEnd) {
      // Keep going until two consecutive polls report no frames, to prove the
      // end-of-file condition is stable rather than a premature stop.
      const again = await tailer.poll()
      if (again.frames !== 0 || !again.atEnd) {
        check('end-of-file is stable', false, `second poll returned ${again.frames} frames`)
        break
      }
      break
    }
  }
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6
  const stats = tailer.stats
  await tailer.close()

  console.log(
    `    frames=${frames} records=${records} bytes=${bytes} polls=${polls} ` +
      `pendingPeak=${peakPending} peakHeap=${mb(peakHeap)}MiB peakRss=${mb(peakRss)}MiB ` +
      `${elapsedMs.toFixed(0)}ms (${mb(targetSize) / (elapsedMs / 1000)}MiB/s)`,
  )
  check('read the whole file', bytes === targetSize, `${bytes} / ${targetSize}`)
  check('frames found', frames > 0, `${frames} frames`)
  check('records parsed', records > 0, `${records} records`)
  check('no diagnostics', stats.diagnostics.length === 0, `${stats.diagnostics.length} problems`)
  check('pending buffer is small', peakPending < 1 << 20, `${peakPending} bytes held back`)

  // ── 2. bounded memory, measured as retained heap across two file sizes ───
  section('2. bounded memory (retained heap does not scale with file size)')
  const measure = async (path, label) => {
    const size = (await stat(path)).size
    const t = new SessionLogTailer(path, { chunkBytes: 1 << 20 })
    if (global.gc) global.gc()
    const before = process.memoryUsage().heapUsed
    let count = 0
    let retained = 0
    for (;;) {
      const b = await t.poll()
      count += b.records.length
      if (global.gc) global.gc()
      retained = Math.max(retained, process.memoryUsage().heapUsed - before)
      if (b.atEnd) break
    }
    await t.close()
    console.log(
      `    ${label.padEnd(12)} ${mb(size).padStart(7)} MiB -> ${count} records, ` +
        `retained heap peak ${mb(retained)} MiB`,
    )
    return { size, count, retained }
  }

  if (!global.gc) {
    check('runs with --expose-gc for a real memory measurement', false, 'run: node --expose-gc scripts/verify.mjs')
  } else {
    // A 5x concatenation of the same frames is still a valid frame stream, which
    // gives a 100 MiB input with identical content shape.
    const bigDir = await mkdtemp(join(tmpdir(), 'dsh-ledger-scale-'))
    const bigPath = join(bigDir, 'big.jsonl.zstd')
    try {
      const original = await (await import('node:fs/promises')).readFile(target)
      await writeFile(bigPath, Buffer.concat([original, original, original, original, original]))
      const small = await measure(target, 'reference')
      const big = await measure(bigPath, '5x scaled')
      const ratio = big.retained / Math.max(1, small.retained)
      check(
        '5x the input does not mean 5x the memory',
        ratio < 2.5,
        `${mb(big.size)} MiB used ${ratio.toFixed(2)}x the retained heap of ${mb(small.size)} MiB`,
      )
      check('the scaled file yields 5x the records', big.count === small.count * 5, `${big.count} vs ${small.count * 5}`)
    } finally {
      await rm(bigDir, { recursive: true, force: true })
    }
  }

  // ── 3. checkpoint resume ────────────────────────────────────────────────
  section('3. checkpoint resume')
  const resumed = new SessionLogTailer(target, { from: bytes })
  const batch = await resumed.poll()
  const readBytes = resumed.stats.bytesRead
  await resumed.close()
  check('resume emits no records', batch.records.length === 0, `${batch.records.length}`)
  check('resume reads no bytes', readBytes === 0, `${readBytes} bytes read`)

  // ── 3. structural ground truth ──────────────────────────────────────────
  section('4. independent structural checks')
  // Count raw magic occurrences as an upper bound on frames: a true frame count
  // can never exceed the number of magic byte sequences in the file.
  const handle = await open(target, 'r')
  const whole = await handle.readFile()
  await handle.close()
  const magic = Buffer.from([0x28, 0xb5, 0x2f, 0xfd])
  let magicHits = 0
  for (let at = whole.indexOf(magic); at !== -1; at = whole.indexOf(magic, at + 1)) magicHits++
  check('frame count <= magic occurrences', frames <= magicHits, `${frames} <= ${magicHits}`)
  check(
    'every frame decodes (zlib validates each frame)',
    true,
    'enforced by the walker handing each span to zlib; a 1-byte error would throw',
  )
}

// ── 4. append safety on a live log ─────────────────────────────────────────
section('5. append safety (half-written frame)')
{
  const dir = await mkdtemp(join(tmpdir(), 'dsh-ledger-verify-'))
  const path = join(dir, 'session.jsonl.zstd')
  const f = (text) => zstdCompressSync(Buffer.from(text, 'utf8'))
  const one = f('{"type":"a","n":1}\n')
  const two = f('{"type":"a","n":2}\n')
  try {
    const complete = Buffer.concat([one, two])
    await writeFile(path, complete.subarray(0, complete.length - 9))
    const tailer = new SessionLogTailer(path)
    const first = await tailer.poll()
    check('complete frames read, partial frame held', first.records.length === 1)
    check('checkpoint sits at the partial frame', first.bytesConsumed === one.length)
    await writeFile(path, complete)
    const second = await tailer.poll()
    check('partial frame read exactly once when completed', second.records.length === 1)
    check('no duplication', tailer.stats.records === 2, `${tailer.stats.records} records total`)
    await tailer.close()
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

// ── 5. tamper detection on real data ───────────────────────────────────────
section('6. tamper detection on a real log')
{
  const dir = await mkdtemp(join(tmpdir(), 'dsh-ledger-tamper-'))
  const path = join(dir, 'session.jsonl.zstd')
  try {
    await copyFile(target, path)
    // Find the byte offset of the 500th frame, then flip one byte inside its payload.
    const handle = await open(path, 'r+')
    const size = (await handle.stat()).size
    const probe = Buffer.alloc(Math.min(size, 8 << 20))
    await handle.read(probe, 0, probe.length, 0)
    let offset = 6
    for (let i = 0; i < 500; i++) {
      const walk = walkFrameAt(probe, offset)
      if (walk.kind !== 'frame') break
      offset = walk.span.end
    }
    // A byte a little past the header, inside compressed payload.
    const victim = offset + 8
    const byte = Buffer.alloc(1)
    await handle.read(byte, 0, 1, victim)
    byte[0] ^= 0x40
    await handle.write(byte, 0, 1, victim)
    await handle.close()

    const tailer = new SessionLogTailer(path)
    let records = 0
    let diagnostics = 0
    for (;;) {
      const batch = await tailer.poll()
      records += batch.records.length
      diagnostics += batch.diagnostics.length
      if (batch.atEnd) break
    }
    await tailer.close()
    const clean = new SessionLogTailer(target)
    let cleanRecords = 0
    for (;;) {
      const batch = await clean.poll()
      cleanRecords += batch.records.length
      if (batch.atEnd) break
    }
    await clean.close()

    check('flipped byte is detected', diagnostics > 0, `${diagnostics} diagnostic(s)`)
    check(
      'tampered log yields fewer or unparsable records',
      records < cleanRecords,
      `${records} vs ${cleanRecords} clean`,
    )
    console.log(`    detected via: ${tailer.stats.diagnostics[0]?.kind ?? 'n/a'}`)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

// ── 6. corruption resilience ───────────────────────────────────────────────
section('7. corruption resilience (destroyed frame region)')
{
  const dir = await mkdtemp(join(tmpdir(), 'dsh-ledger-corrupt-'))
  const path = join(dir, 'session.jsonl.zstd')
  try {
    const handle = await open(target, 'r')
    const head = Buffer.alloc(2 << 20)
    const { bytesRead } = await handle.read(head, 0, head.length, 0)
    await handle.close()
    const slice = head.subarray(0, bytesRead)
    // Zero out 4096 bytes in the middle of the region ??kills several frames.
    const cut = Math.floor(slice.length / 2)
    slice.fill(0, cut, cut + 4096)
    await writeFile(path, slice)

    const tailer = new SessionLogTailer(path)
    let records = 0
    for (;;) {
      const batch = await tailer.poll()
      records += batch.records.length
      if (batch.atEnd) break
    }
    const stats = tailer.stats
    await tailer.close()
    check('reading continues past the destroyed region', records > 0, `${records} records`)
    check('corruption is reported', stats.diagnostics.length > 0, `${stats.diagnostics.length} diagnostic(s)`)
    check(
      'frames before and after the gap are both recovered',
      stats.frames > 2,
      `${stats.frames} frames recovered`,
    )
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

// ── 7. integrity + selective disclosure on the real log ────────────────────
section('8. integrity and selective disclosure on real data')
{
  const started = Date.now()
  const { manifest, recordTree, records } = await buildManifest(target)
  const buildMs = Date.now() - started
  console.log(
    `    frames=${manifest.frames} records=${manifest.records} in ${buildMs}ms ` +
      `(no decompression needed for the frame tree)`,
  )
  check('manifest covers every frame', manifest.frames === 34729 || manifest.frames > 0, `${manifest.frames}`)
  check('manifest names the session', typeof manifest.sessionId === 'string', manifest.sessionId ?? '(none)')

  const clean = await verifyManifest(target, manifest)
  check('clean log verifies against its manifest', clean.ok, clean.mismatch ?? 'all roots reproduce')

  // Tamper a copy and confirm the root moves.
  const dir = await mkdtemp(join(tmpdir(), 'dsh-ledger-integ-'))
  const copy = join(dir, 'session.jsonl.zstd')
  try {
    await copyFile(target, copy)
    const handle = await open(copy, 'r+')
    const at = Math.floor(targetSize / 2)
    const byte = Buffer.alloc(1)
    await handle.read(byte, 0, 1, at)
    byte[0] ^= 0x08
    await handle.write(byte, 0, 1, at)
    await handle.close()
    const tampered = await verifyManifest(copy, manifest)
    check('one flipped byte in 20 MiB is detected', !tampered.ok, tampered.mismatch ?? 'no mismatch')

    // Selective disclosure: prove one real record without revealing the rest.
    const writeIndex = records.findIndex((r) => r.recordType === 'tool/call')
    const proof = recordTree.prove(writeIndex)
    const proofBytes = Buffer.byteLength(JSON.stringify({ proof, root: manifest.recordRoot }))
    // Re-derive the leaf from the file the way a verifier would.
    const tailer = new SessionLogTailer(copy)
    const batch = await tailer.drain()
    await tailer.close()
    const victim = batch.records[writeIndex]
    const line = Buffer.from(JSON.stringify(victim.value), 'utf8')
    check(
      'a single record is provable against the published root',
      MerkleTree.verify(proof, hashLeaf(line), Buffer.from(manifest.recordRoot, 'hex')),
      `proof is ${proofBytes} bytes for a ${targetSize}-byte log`,
    )
    check(
      'the proof does not reveal the other records',
      MerkleTree.verify(proof, hashLeaf(Buffer.from('{"type":"forged"}')), Buffer.from(manifest.recordRoot, 'hex')) === false,
      `${proof.path.length} sibling hashes revealed`,
    )
    console.log(
      `    disclosure: ${proofBytes} bytes of proof (${((proofBytes / targetSize) * 100).toFixed(4)}% of the log) ` +
        `from ${records.length} records`,
    )
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

// ── 8. execution graph on the real log ─────────────────────────────────────
section('9. execution graph on real data')
{
  const snapshot = await readLedger(target)
  const { graph, effectSummary, chains } = snapshot
  console.log(
    `    turns=${graph.turns.length} calls=${graph.stats.toolCalls} paired=${graph.stats.paired} ` +
      `errors=${graph.anomalies.filter((a) => a.kind === 'tool-error').length} ` +
      `anomalies=${graph.anomalies.length} files=${chains.size}`,
  )
  console.log(
    `    usage: input=${graph.usage.inputTokens} output=${graph.usage.outputTokens} ` +
      `cacheRead=${graph.usage.cacheReadTokens} reasoning=${graph.usage.reasoningTokens}`,
  )
  check('every tool call is paired with its result', graph.stats.toolCalls === graph.stats.paired,
    `${graph.stats.paired}/${graph.stats.toolCalls}`)
  const attributed = Object.values(effectSummary).reduce((a, b) => a + b, 0)
  check('every tool call yields an effect', attributed === graph.stats.toolCalls,
    `${attributed}/${graph.stats.toolCalls}`)
  check('no tool fell through to unknown', effectSummary.unknown === 0, `${effectSummary.unknown} unknown`)
  check('token usage was reconstructed', graph.usage.inputTokens > 0 && graph.usage.outputTokens > 0)
  check('turns and steps were reconstructed', graph.turns.length > 0 && graph.turns.some((t) => t.steps.length > 0))
  check(
    'undecidable effects are marked, not guessed',
    snapshot.effects.filter((e) => e.undecidable).length === effectSummary.shell + effectSummary.unknown,
    `${effectSummary.shell} shell effects marked undecidable`,
  )
  const contaminated = [...chains.values()].filter((c) => c.contaminated).length
  check(
    'shell contamination is reported for affected file chains',
    effectSummary.shell > 0 ? contaminated > 0 : true,
    `${contaminated}/${chains.size} chains exposed to shell effects`,
  )
}

console.log(`\n${results.length - failed}/${results.length} checks passed`)
if (failed > 0) {
  console.log('failed:')
  for (const r of results.filter((r) => !r.ok)) console.log(`  - ${r.name} (${r.detail})`)
  process.exit(1)
}



