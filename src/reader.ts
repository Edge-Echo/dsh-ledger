// dsh-ledger — incremental, crash-safe reader for append-only frame logs.
//
// The tailer owns a small amount of state and nothing else:
//
//   carry      unconsumed bytes, beginning at the first byte of an *incomplete*
//              frame. Bounded by `maxFrameBytes` — never the whole file.
//   lineCarry  a trailing partial JSONL line, in case a record straddles a frame
//              boundary (defensive; DSH writes whole lines per append).
//   consumed   absolute offset to resume from — the durability checkpoint.
//
// That checkpoint is what makes this different from decode-the-whole-file
// approaches: a restart resumes at an exact frame boundary instead of re-reading
// and re-decoding the entire log, and a half-written tail frame is simply held
// back until the writer finishes it.
import { open, type FileHandle } from 'node:fs/promises'
import { decodeFrame, findNextFrameMagic, walkFrameAt, type FrameSpan } from './frames.js'

/** A record with provenance: where in the file it came from. */
export interface RawRecord {
  value: unknown
  /** Zero-based index of the frame that carried this record. */
  frameIndex: number
  /** Absolute byte offset of that frame's magic number. */
  frameStart: number
}

export type DiagnosticKind = 'corrupt' | 'oversize-frame' | 'bad-json'

export interface Diagnostic {
  kind: DiagnosticKind
  /** Absolute byte offset where the problem was observed. */
  offset: number
  detail: string
  /** Bytes skipped while resynchronising (0 when nothing was skipped). */
  skippedBytes: number
}

export interface TailBatch {
  records: RawRecord[]
  /** Frames fully consumed during this call. */
  frames: number
  /** Absolute offset just past the last complete frame — persist this. */
  bytesConsumed: number
  /** Bytes held back as an incomplete frame (or an incomplete record line). */
  pendingBytes: number
  diagnostics: Diagnostic[]
  /**
   * True when reading reached the current end of the file. Callers stop here
   * when draining; a live tailer calls `poll()` again later, since the writer
   * may have appended more. A partial tail frame does not make this false — it
   * is simply held back until the writer completes it.
   */
  atEnd: boolean
}

export interface TailerOptions {
  /** Read granularity in bytes. Default 1 MiB. */
  chunkBytes?: number
  /**
   * Refuse to hold more than this many bytes for a single incomplete frame.
   * Exceeding it means the "frame" is really a corrupt region, so the tailer
   * resynchronises instead of growing without bound. Default 64 MiB.
   */
  maxFrameBytes?: number
  /**
   * How many bytes to read ahead before consuming frames, as a multiple of
   * `chunkBytes`. Caps the memory a single `poll()` can allocate. Default 4.
   */
  readAheadChunks?: number
  /** Absolute byte offset to start reading from (a previous checkpoint). */
  from?: number
}

export interface TailerStats {
  frames: number
  records: number
  /** Durable checkpoint: offset to resume from. */
  bytesConsumed: number
  /** Bytes read from disk in total (may exceed bytesConsumed after corruption). */
  bytesRead: number
  /** Bytes currently held back. */
  pendingBytes: number
  /** Problems seen so far, in file order. */
  diagnostics: Diagnostic[]
}

const NEWLINE = 0x0a

export class SessionLogTailer {
  readonly path: string
  private handle: FileHandle | null = null
  private readonly chunkBytes: number
  private readonly maxFrameBytes: number
  private readonly readAhead: number

  /** Unconsumed bytes; carry[0] sits at absolute offset `carryOffset`. */
  private carry: Buffer = Buffer.alloc(0)
  private carryOffset = 0
  /** Next byte to read from the file. */
  private readPos = 0
  /** Trailing partial line from the previous frame. */
  private lineCarry = ''
  /** Checkpoint: resume offset. */
  private consumed = 0

  private frames = 0
  private recordCount = 0
  private bytesRead = 0
  private allDiagnostics: Diagnostic[] = []
  private pendingRecords: RawRecord[] = []
  private reportedFrames = 0

  constructor(path: string, opts: TailerOptions = {}) {
    this.path = path
    this.chunkBytes = opts.chunkBytes ?? 1 << 20
    this.maxFrameBytes = opts.maxFrameBytes ?? 64 << 20
    this.readAhead = Math.max(1, opts.readAheadChunks ?? 4)
    const from = opts.from ?? 0
    this.carryOffset = from
    this.readPos = from
    this.consumed = from
  }

  async open(): Promise<void> {
    if (!this.handle) this.handle = await open(this.path, 'r')
  }

  async close(): Promise<void> {
    const h = this.handle
    this.handle = null
    if (h) await h.close()
  }

  get stats(): TailerStats {
    return {
      frames: this.frames,
      records: this.recordCount,
      bytesConsumed: this.consumed,
      bytesRead: this.bytesRead,
      pendingBytes: this.carry.length + Buffer.byteLength(this.lineCarry),
      diagnostics: [...this.allDiagnostics],
    }
  }

  /**
   * Read whatever is new and complete. Safe to call repeatedly against a live
   * log, and safe to call after a crash: resumes from the checkpoint.
   *
   * Reads at most `readAheadChunks * chunkBytes` before consuming, so a large
   * log streams through in bounded memory. Call until `atEnd` for a full sweep.
   */
  async poll(): Promise<TailBatch> {
    if (!this.handle) await this.open()
    const handle = this.handle!
    const diagnostics: Diagnostic[] = []
    let atEnd = false
    // ── phase 1: fill ──────────────────────────────────────────────────────
    // Always attempt at least one read: if the buffer sits at the budget with no
    // complete frame in it, refusing to read would spin without progressing.
    const budget = this.chunkBytes * this.readAhead
    let first = true
    while (first || this.carry.length < budget) {
      first = false
      const chunk = Buffer.allocUnsafe(this.chunkBytes)
      const { bytesRead } = await handle.read(chunk, 0, this.chunkBytes, this.readPos)
      if (bytesRead === 0) {
        atEnd = true
        break
      }
      this.bytesRead += bytesRead
      const piece = bytesRead === chunk.length ? chunk : chunk.subarray(0, bytesRead)
      this.carry = this.carry.length === 0 ? piece : Buffer.concat([this.carry, piece])
      this.readPos += bytesRead
    }

    // ── phase 2: consume every complete frame now buffered ────────────────
    for (;;) {
      const walk = walkFrameAt(this.carry, 0)
      if (walk.kind === 'frame') {
        this.consumeFrame(walk.span, diagnostics)
        continue
      }
      if (walk.kind === 'incomplete' || walk.kind === 'eof') break
      this.resync('corrupt', walk.reason, diagnostics)
    }

    // ── phase 3: bounded memory ────────────────────────────────────────────
    if (this.carry.length > this.maxFrameBytes) {
      this.resync(
        'oversize-frame',
        `frame exceeds maxFrameBytes (${this.maxFrameBytes})`,
        diagnostics,
      )
      atEnd = false
    }
    this.compact()

    const batch: TailBatch = {
      records: this.pendingRecords,
      frames: this.frames - this.reportedFrames,
      bytesConsumed: this.consumed,
      pendingBytes: this.carry.length + Buffer.byteLength(this.lineCarry),
      diagnostics,
      atEnd,
    }
    this.pendingRecords = []
    this.reportedFrames = this.frames
    this.allDiagnostics.push(...diagnostics)
    return batch
  }

  /** Drain the whole file, however many polls that takes. */
  async drain(): Promise<TailBatch> {
    const records: RawRecord[] = []
    const diagnostics: Diagnostic[] = []
    let frames = 0
    let atEnd = false
    for (;;) {
      const batch = await this.poll()
      records.push(...batch.records)
      diagnostics.push(...batch.diagnostics)
      frames += batch.frames
      atEnd = batch.atEnd
      if (batch.atEnd) break
    }
    return {
      records,
      frames,
      bytesConsumed: this.consumed,
      pendingBytes: this.carry.length + Buffer.byteLength(this.lineCarry),
      diagnostics,
      atEnd,
    }
  }

  /** Skip forward to the next frame magic after a structural problem. */
  private resync(kind: DiagnosticKind, detail: string, diagnostics: Diagnostic[]): void {
    const next = findNextFrameMagic(this.carry, 1)
    const skipped = next === -1 ? this.carry.length : next
    diagnostics.push({ kind, offset: this.carryOffset, detail, skippedBytes: skipped })
    this.carry = next === -1 ? Buffer.alloc(0) : this.carry.subarray(next)
    this.carryOffset += skipped
    // The skipped region is not part of any frame; treat the checkpoint as
    // advanced so a restart does not re-scan known garbage.
    this.consumed = Math.max(this.consumed, this.carryOffset)
  }

  /**
   * Decode one complete frame, split it into JSONL records, and advance the
   * checkpoint. Called only with a structurally valid span.
   */
  private consumeFrame(span: FrameSpan, diagnostics: Diagnostic[]): void {
    const absoluteStart = this.carryOffset + span.start
    let text: string
    try {
      text = decodeFrame(this.carry, span)
    } catch (err) {
      diagnostics.push({
        kind: 'corrupt',
        offset: absoluteStart,
        detail: `frame decode failed: ${(err as Error).message}`,
        skippedBytes: 0,
      })
      // The structure was valid even though the payload was not. Stepping over
      // it keeps us frame-aligned, which is what keeps the rest of the log usable.
      this.carry = this.carry.subarray(span.end)
      this.carryOffset += span.end
      this.consumed = this.carryOffset
      this.frames++
      return
    }

    const lines: string[] = []
    let start = 0
    for (let i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) === NEWLINE) {
        lines.push(text.slice(start, i))
        start = i + 1
      }
    }
    const trailing = text.slice(start)
    if (this.lineCarry.length > 0) lines[0] = this.lineCarry + (lines[0] ?? '')
    this.lineCarry = trailing

    const frameIndex = this.frames
    for (const line of lines) {
      const trimmed = line.trim()
      if (trimmed.length === 0) continue
      try {
        this.pendingRecords.push({
          value: JSON.parse(trimmed),
          frameIndex,
          frameStart: absoluteStart,
        })
        this.recordCount++
      } catch (err) {
        diagnostics.push({
          kind: 'bad-json',
          offset: absoluteStart,
          detail: `unparsable record: ${(err as Error).message}`,
          skippedBytes: 0,
        })
      }
    }

    this.frames++
    this.carry = this.carry.subarray(span.end)
    this.carryOffset += span.end
    // A partial line means the next frame holds its remainder, so the durable
    // checkpoint must stay behind this frame and let it be replayed.
    this.consumed = this.lineCarry.length === 0 ? this.carryOffset : absoluteStart
  }

  private compact(): void {
    // subarray() shares the parent ArrayBuffer; copy now and then so a
    // long-running tailer does not pin every chunk it has ever read.
    if (this.carry.length === 0) {
      this.carry = Buffer.alloc(0)
      return
    }
    const backing = this.carry.buffer.byteLength
    if (backing > this.chunkBytes * 2 && this.carry.length * 4 < backing) {
      this.carry = Buffer.from(this.carry)
    }
  }

  /** Discard all state and start over, e.g. when a checkpoint is stale. */
  async rewind(from = 0): Promise<void> {
    await this.close()
    this.carry = Buffer.alloc(0)
    this.carryOffset = from
    this.readPos = from
    this.consumed = from
    this.lineCarry = ''
    this.frames = 0
    this.recordCount = 0
    this.bytesRead = 0
    this.allDiagnostics = []
    this.pendingRecords = []
    this.reportedFrames = 0
  }
}
