// Tests for the zstd frame walker and the incremental tailer.
import assert from 'node:assert/strict'
import { mkdtemp, open, rm, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { zstdCompressSync } from 'node:zlib'

import {
  ZSTD_MAGIC,
  decodeFrame,
  findNextFrameMagic,
  walkFrameAt,
} from '../lib/frames.js'
import { SessionLogTailer } from '../lib/reader.js'

const frame = (text) => zstdCompressSync(Buffer.from(text, 'utf8'))

/** A well-formed skippable frame. */
const skippable = (payload) => {
  const head = Buffer.alloc(8)
  head.writeUInt32LE(0x184d2a50, 0)
  head.writeUInt32LE(payload.length, 4)
  return Buffer.concat([head, payload])
}

async function withTempFile(contents, fn) {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-ledger-'))
  const path = join(dir, 'session.jsonl.zstd')
  await writeFile(path, contents)
  try {
    return await fn(path)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

/** Append bytes to a file the way a log writer does. */
async function append(path, bytes) {
  const handle = await open(path, 'a')
  try {
    await handle.write(bytes)
  } finally {
    await handle.close()
  }
}

test('walkFrameAt finds the exact span of a single frame', () => {
  const text = '{"type":"user"}\n'
  const buf = frame(text)
  const walk = walkFrameAt(buf, 0)
  assert.equal(walk.kind, 'frame')
  assert.equal(walk.span.start, 0)
  assert.equal(walk.span.end, buf.length)
  assert.equal(walk.span.skippable, false)
  assert.ok(walk.span.blocks >= 1)
  if (walk.span.contentSize !== undefined) {
    assert.equal(walk.span.contentSize, Buffer.byteLength(text))
  }
  assert.equal(decodeFrame(buf, walk.span), text)
})

test('walkFrameAt reports an incomplete frame instead of throwing', () => {
  const buf = frame('{"a":1}\n')
  for (const cut of [1, 4, 5, 8, buf.length - 1]) {
    const walk = walkFrameAt(buf.subarray(0, cut), 0)
    assert.equal(walk.kind, 'incomplete', `cut=${cut}`)
    assert.ok(walk.needBytes > 0)
  }
})

test('walkFrameAt rejects garbage and the reserved header bit', () => {
  const bad = Buffer.from('not a frame at all!!')
  assert.equal(walkFrameAt(bad, 0).kind, 'corrupt')

  const buf = frame('{"a":1}\n')
  const tampered = Buffer.from(buf)
  tampered[4] |= 0x08 // reserved bit in Frame_Header_Descriptor
  const walk = walkFrameAt(tampered, 0)
  assert.equal(walk.kind, 'corrupt')
  assert.match(walk.reason, /reserved bit/)
})

test('walkFrameAt walks skippable frames', () => {
  const payload = Buffer.from('vendor metadata')
  const buf = skippable(payload)
  const walk = walkFrameAt(buf, 0)
  assert.equal(walk.kind, 'frame')
  assert.equal(walk.span.skippable, true)
  assert.equal(walk.span.end, buf.length)
  assert.equal(decodeFrame(buf, walk.span), '')
})

test('findNextFrameMagic locates a resynchronisation point', () => {
  const buf = Buffer.concat([Buffer.from([0xde, 0xad, 0xbe, 0xef]), frame('{"a":1}\n')])
  const at = findNextFrameMagic(buf, 1)
  assert.equal(at, 4)
  assert.equal(buf.readUInt32LE(at), ZSTD_MAGIC)
  assert.equal(findNextFrameMagic(Buffer.from([1, 2, 3]), 0), -1)
})

test('tailer reads a multi-frame log completely', async () => {
  const records = Array.from({ length: 50 }, (_, i) => ({ i, type: 'user' }))
  const contents = Buffer.concat(records.map((r) => frame(JSON.stringify(r) + '\n')))
  await withTempFile(contents, async (path) => {
    const tailer = new SessionLogTailer(path)
    const batch = await tailer.drain()
    await tailer.close()
    assert.equal(batch.frames, 50)
    assert.equal(batch.records.length, 50)
    assert.deepEqual(
      batch.records.map((r) => r.value),
      records,
    )
    assert.equal(batch.diagnostics.length, 0)
    assert.equal(batch.atEnd, true)
    // Provenance points at real frame boundaries.
    for (const rec of batch.records) {
      assert.equal(contents.readUInt32LE(rec.frameStart), ZSTD_MAGIC)
    }
  })
})

test('tailer resumes after an append without duplicating records', async () => {
  await withTempFile(frame('{"n":1}\n'), async (path) => {
    const tailer = new SessionLogTailer(path)
    const first = await tailer.poll()
    assert.equal(first.records.length, 1)
    assert.equal(first.frames, 1)
    assert.equal(first.atEnd, true)

    await append(path, frame('{"n":2}\n'))
    const second = await tailer.poll()
    assert.equal(second.records.length, 1)
    assert.equal(second.frames, 1)
    assert.equal(second.records[0].value.n, 2)

    await append(path, Buffer.concat([frame('{"n":3}\n'), frame('{"n":4}\n')]))
    const third = await tailer.poll()
    assert.deepEqual(
      third.records.map((r) => r.value.n),
      [3, 4],
    )
    assert.equal(third.frames, 2)

    const idle = await tailer.poll()
    assert.equal(idle.records.length, 0)
    assert.equal(idle.frames, 0)
    assert.equal(idle.atEnd, true)

    assert.equal(tailer.stats.frames, 4)
    assert.equal(tailer.stats.records, 4)
    await tailer.close()
  })
})

test('tailer holds back a half-written frame, then reads it once completed', async () => {
  const whole = Buffer.concat([frame('{"keep":1}\n'), frame('{"keep":2}\n'), frame('{"keep":3}\n')])
  const thirdStart = frame('{"keep":1}\n').length + frame('{"keep":2}\n').length
  const partial = whole.subarray(0, whole.length - 12)

  await withTempFile(partial, async (path) => {
    const tailer = new SessionLogTailer(path)
    const batch = await tailer.poll()
    assert.deepEqual(
      batch.records.map((r) => r.value.keep),
      [1, 2],
    )
    assert.equal(batch.frames, 2)
    assert.ok(batch.pendingBytes > 0, 'the partial third frame is held back')
    // The checkpoint must sit at the third frame's start, not past it.
    assert.equal(batch.bytesConsumed, thirdStart)

    const checkpoint = batch.bytesConsumed
    await append(path, whole.subarray(whole.length - 12))
    const resumed = await tailer.poll()
    assert.deepEqual(
      resumed.records.map((r) => r.value.keep),
      [3],
    )
    assert.equal(resumed.frames, 1)
    assert.equal(resumed.pendingBytes, 0)
    assert.equal(resumed.bytesConsumed, whole.length)
    assert.ok(resumed.bytesConsumed > checkpoint)
    await tailer.close()
  })
})

test('tailer restarted from a checkpoint does not re-read the whole file', async () => {
  const contents = Buffer.concat(
    Array.from({ length: 20 }, (_, i) => frame(JSON.stringify({ i }) + '\n')),
  )
  await withTempFile(contents, async (path) => {
    const first = new SessionLogTailer(path)
    const batch = await first.drain()
    await first.close()
    assert.equal(batch.records.length, 20)

    // Resume from the checkpoint: nothing new should be read.
    const second = new SessionLogTailer(path, { from: batch.bytesConsumed })
    const resumed = await second.drain()
    await second.close()
    assert.equal(resumed.records.length, 0)
    assert.equal(resumed.frames, 0)
    assert.equal(second.stats.bytesRead, 0)

    // Resume from mid-file: only frames 10..19 are re-read, because frame 10's
    // own boundary is where the new checkpoint points.
    const third = new SessionLogTailer(path, { from: batch.records[10].frameStart })
    const tail = await third.drain()
    await third.close()
    assert.deepEqual(
      tail.records.map((r) => r.value.i),
      Array.from({ length: 10 }, (_, k) => k + 10),
    )
    assert.ok(third.stats.bytesRead < contents.length)
  })
})

test('tailer survives a corrupt region and keeps reading', async () => {
  const good = (n) => frame(JSON.stringify({ n }) + '\n')
  const garbage = Buffer.from('<<<this is not a frame>>>')
  const contents = Buffer.concat([good(1), garbage, good(2), good(3)])
  await withTempFile(contents, async (path) => {
    const tailer = new SessionLogTailer(path, { chunkBytes: 32 })
    const batch = await tailer.drain()
    await tailer.close()
    assert.deepEqual(
      batch.records.map((r) => r.value.n),
      [1, 2, 3],
    )
    assert.equal(batch.frames, 3)
    const corrupt = batch.diagnostics.filter((d) => d.kind === 'corrupt')
    assert.equal(corrupt.length, 1)
    assert.equal(corrupt[0].skippedBytes, garbage.length)
    assert.equal(corrupt[0].offset, good(1).length)
  })
})

test('tailer reassembles a record that straddles a frame boundary', async () => {
  const contents = Buffer.concat([frame('{"a":1}\n{"b":'), frame('2}\n{"a":3}\n')])
  await withTempFile(contents, async (path) => {
    const tailer = new SessionLogTailer(path)
    const batch = await tailer.drain()
    await tailer.close()
    assert.deepEqual(batch.records.map((r) => r.value), [{ a: 1 }, { b: 2 }, { a: 3 }])
  })
})

test('tailer coalesces frames across small read chunks', async () => {
  const contents = Buffer.concat(
    Array.from({ length: 30 }, (_, i) => frame(JSON.stringify({ i, pad: 'x'.repeat(200) }) + '\n')),
  )
  await withTempFile(contents, async (path) => {
    const tailer = new SessionLogTailer(path, { chunkBytes: 17, readAheadChunks: 1 })
    const batch = await tailer.drain()
    await tailer.close()
    assert.equal(batch.frames, 30)
    assert.equal(batch.records.length, 30)
    assert.equal(batch.diagnostics.length, 0)
    assert.equal(batch.atEnd, true)
  })
})

test('tailer reports skippable frames without emitting records', async () => {
  const contents = Buffer.concat([
    skippable(Buffer.from('metadata')),
    frame('{"ok":true}\n'),
    skippable(Buffer.alloc(0)),
    frame('{"ok":false}\n'),
  ])
  await withTempFile(contents, async (path) => {
    const tailer = new SessionLogTailer(path)
    const batch = await tailer.drain()
    await tailer.close()
    assert.equal(batch.records.length, 2)
    assert.deepEqual(batch.records.map((r) => r.value.ok), [true, false])
  })
})

test('tailer stays within its memory budget on a long log', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-ledger-big-'))
  const path = join(dir, 'session.jsonl.zstd')
  try {
    const handle = await open(path, 'w')
    for (let i = 0; i < 4000; i++) {
      await handle.write(frame(JSON.stringify({ i, pad: 'y'.repeat(300) }) + '\n'))
    }
    await handle.close()

    const tailer = new SessionLogTailer(path, { chunkBytes: 1 << 16, readAheadChunks: 2 })
    let seen = 0
    let peakPending = 0
    for (;;) {
      const batch = await tailer.poll()
      seen += batch.records.length
      peakPending = Math.max(peakPending, batch.pendingBytes)
      if (batch.atEnd) break
    }
    await tailer.close()
    assert.equal(seen, 4000)
    assert.ok(peakPending < 1 << 16, `pending ${peakPending} should stay under one chunk`)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('reads a real DSH session log when one is available', async (t) => {
  const candidates = process.env.DSH_LEDGER_TEST_LOG ? [process.env.DSH_LEDGER_TEST_LOG] : []
  const globbed = process.env.DSH_LEDGER_TEST_GLOB
  if (globbed) candidates.push(globbed)
  const path = candidates.find((p) => p && existsSync(p))
  if (!path) {
    t.skip('set DSH_LEDGER_TEST_LOG to a session.jsonl.zstd to run this')
    return
  }
  const tailer = new SessionLogTailer(path)
  const batch = await tailer.drain()
  const stats = tailer.stats
  await tailer.close()
  assert.ok(stats.frames > 0)
  assert.equal(stats.records, batch.records.length)
  assert.ok(batch.atEnd)
  t.diagnostic(`frames=${stats.frames} records=${stats.records} bytes=${stats.bytesConsumed}`)
  // Every record must carry a real frame boundary.
  const handle = await open(path, 'r')
  const head = Buffer.alloc(4)
  for (const rec of [batch.records[0], batch.records[batch.records.length - 1]]) {
    await handle.read(head, 0, 4, rec.frameStart)
    assert.equal(head.readUInt32LE(0), ZSTD_MAGIC)
  }
  await handle.close()
})
