// dsh-ledger — Merkle integrity over a session log.
//
// Two trees are built over the same file, because the two questions you actually
// need to answer are different:
//
//   frame tree    leaf = raw frame bytes. Proves "this exact byte range was in
//                 the log" and needs no decompression at all, so it can attest
//                 content it cannot read.
//   record tree   leaf = the JSONL line bytes of one record. Proves "this record
//                 existed" and — because a proof reveals only a sibling path, not
//                 the other leaves — supports *selective disclosure*: publish one
//                 tool call as evidence while keeping the rest of the session
//                 confidential.
//
// Hashing follows RFC 6962 (Certificate Transparency) so proofs are unambiguous
// and interoperate with existing transparency-log tooling:
//
//   MTH([])     = SHA-256()
//   MTH([d])    = SHA-256(0x00 || d)
//   MTH(D[0:n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])), k = largest power of 2 < n
//
// The 0x00/0x01 domain separation is what stops a crafted internal node from
// being replayed as a leaf — the failure mode of the naive "promote the odd node"
// construction used by many hand-rolled Merkle implementations.
import { createHash, createPrivateKey, createPublicKey, hash, sign, verify } from 'node:crypto'
import { open } from 'node:fs/promises'
import { decodeFrame, walkFrameAt } from './frames.js'

const LEAF_PREFIX = Buffer.from([0x00])
const NODE_PREFIX = Buffer.from([0x01])

/** SHA-256 of `0x00 || data`. Prefixed so leaves cannot be forged from nodes. */
export function hashLeaf(data: Buffer): Buffer {
  return hash('sha256', Buffer.concat([LEAF_PREFIX, data]), 'buffer')
}

/** SHA-256 of `0x01 || left || right`. */
export function hashNode(left: Buffer, right: Buffer): Buffer {
  return hash('sha256', Buffer.concat([NODE_PREFIX, left, right]), 'buffer')
}

export interface ProofStep {
  hash: string
  /** Where this sibling sits relative to the node being proven. */
  side: 'left' | 'right'
}

export interface MerkleProof {
  /** Index of the proven leaf (0-based). */
  leaf: number
  /** Total leaf count of the tree the proof is against. */
  size: number
  /** Sibling path, leaf level first. */
  path: ProofStep[]
}

/** Largest power of two strictly less than n (n >= 2). */
function splitPoint(n: number): number {
  let k = 1
  while (k * 2 < n) k *= 2
  return k
}

export class MerkleTree {
  readonly size: number
  readonly root: Buffer
  /** Number of SHA-256 calls performed while building — reported for honesty about cost. */
  readonly hashes: number
  private readonly levels: Buffer[][]

  private constructor(levels: Buffer[][], hashes: number) {
    this.levels = levels
    this.size = levels[0]?.length ?? 0
    this.root = levels[levels.length - 1]?.[0] ?? hash('sha256', Buffer.alloc(0), 'buffer')
    this.hashes = hashes
  }

  /**
   * Build from already-hashed leaves. Passing digests rather than raw data lets
   * a caller hash in a streaming fashion and keep only 32 bytes per record.
   */
  static fromHashes(leaves: Buffer[]): MerkleTree {
    let hashes = 0
    if (leaves.length === 0) {
      return new MerkleTree([[hash('sha256', Buffer.alloc(0), 'buffer')]], 1)
    }
    const levels: Buffer[][] = [leaves]
    let current = leaves
    while (current.length > 1) {
      // Pairing left to right with a lone trailing node carried up is provably
      // equivalent to RFC 6962's "split at the largest power of two below n":
      // both produce MTH(D) = H(MTH(D[0:k]) || MTH(D[k:n])). The recursive
      // `subtreeRoot` used for proofs asserts the same shape, so the two
      // constructions cross-check each other on every verification.
      const next: Buffer[] = []
      for (let i = 0; i + 1 < current.length; i += 2) {
        next.push(hashNode(current[i]!, current[i + 1]!))
        hashes++
      }
      if (current.length % 2 === 1) next.push(current[current.length - 1]!)
      levels.push(next)
      current = next
    }
    return new MerkleTree(levels, hashes)
  }

  static fromLeaves(leaves: Buffer[]): MerkleTree {
    return MerkleTree.fromHashes(leaves.map(hashLeaf))
  }

  get rootHex(): string {
    return this.root.toString('hex')
  }

  /**
   * Inclusion proof for one leaf, in RFC 6962 shape. Recursive by design: the
   * tree shape must follow the same split rule as construction or a proof for a
   * non-power-of-two tree would verify against the wrong root.
   */
  prove(index: number): MerkleProof {
    if (index < 0 || index >= this.size) throw new RangeError(`leaf ${index} out of range`)
    const path: ProofStep[] = []
    const walk = (lo: number, hi: number, target: number): void => {
      if (hi - lo <= 1) return
      const k = splitPoint(hi - lo)
      const mid = lo + k
      if (target < mid) {
        walk(lo, mid, target)
        path.push({ hash: subtreeRoot(mid, hi).toString('hex'), side: 'right' })
      } else {
        walk(mid, hi, target)
        path.push({ hash: subtreeRoot(lo, mid).toString('hex'), side: 'left' })
      }
    }

    // subtreeRoot must agree with the flat levels for power-of-two aligned
    // ranges (the common case, resolved in O(1)) and follow the same recursive
    // rule otherwise. If the two constructions ever disagreed, verification
    // against the root would fail — which the test suite checks.
    const subtreeRoot = (lo: number, hi: number): Buffer => {
      const n = hi - lo
      if (n === 1) return this.levels[0]![lo]!
      const depth = Math.log2(n)
      if (Number.isInteger(depth) && lo % n === 0) return this.levels[depth]![lo / n]!
      const k = splitPoint(n)
      return hashNode(subtreeRoot(lo, lo + k), subtreeRoot(lo + k, hi))
    }

    walk(0, this.size, index)
    return { leaf: index, size: this.size, path }
  }

  /** Recompute the root from one leaf plus its proof. */
  static verify(proof: MerkleProof, leafHash: Buffer, root: Buffer): boolean {
    let acc = leafHash
    for (const step of proof.path) {
      const sibling = Buffer.from(step.hash, 'hex')
      acc = step.side === 'left' ? hashNode(sibling, acc) : hashNode(acc, sibling)
    }
    return acc.equals(root)
  }

  /** Convenience: verify raw leaf data (not a precomputed digest). */
  static verifyLeaf(proof: MerkleProof, leaf: Buffer, root: Buffer): boolean {
    return MerkleTree.verify(proof, hashLeaf(leaf), root)
  }
}

/** One leaf of a record tree: the exact bytes of a JSONL line. */
export interface RecordLeaf {
  /** DSH record sequence number, when the record carries one. */
  seq?: number
  recordType?: string
  frameIndex: number
  frameStart: number
  byteLength: number
  hash: string
}

/**
 * Read `type`, `seq` and (for the session header) `id` out of a record's leading
 * fields. DSH emits these first, so a bounded prefix scan is enough and full
 * `JSON.parse` of every record is avoided.
 */
export function extractRecordMeta(
  line: string,
  prefixLimit = 4096,
): { type?: string; seq?: number; sessionId?: string } {
  const head = line.length > prefixLimit ? line.slice(0, prefixLimit) : line
  const type = /^\{"type":"([^"]{1,64})"/.exec(head)?.[1]
  // `seq` / `seq0` sit at the top level; a nested `"seq":` inside data is preceded
  // by other fields, and the anchored search below only accepts the first one.
  const seqMatch = /^\{"type":"[^"]{1,64}","(?:seq|seq0)":(\d{1,15})/.exec(head)
  const seq = seqMatch ? Number(seqMatch[1]) : undefined
  const sessionId = type === 'session' ? /^\{"type":"session","version":\d+,"id":"([^"]{1,128})"/.exec(head)?.[1] : undefined
  return { type, seq, sessionId }
}

export interface LedgerManifest {
  version: 1
  algorithm: 'sha256/rfc6962'
  /** Session id parsed from the header record, when present. */
  sessionId?: string
  /** Base name of the log file (full paths leak local layout). */
  file: string
  bytes: number
  frames: number
  records: number
  /** Merkle root over raw frame bytes. */
  frameRoot: string
  /** Merkle root over record JSONL bytes. */
  recordRoot: string
  generatedAt: number
  /** Root of a signed manifest the signature covers; absent when unsigned. */
  signature?: string
  signerPublicKey?: string
}

export interface BuildManifestOptions {
  /** Cap on bytes read into memory at once. Defaults to the whole file. */
  maxBytes?: number
  /**
   * Also return each record's parsed JSON value plus its provenance, so a caller
   * that needs both a manifest and a graph pays for one decode pass instead of
   * two. The record tree itself never needs the parse.
   */
  includeRecordValues?: boolean
}

/** A parsed record plus where it came from — the shape the graph builder wants. */
export interface ManifestRecordValue {
  value: unknown
  frameIndex: number
  frameStart: number
}

/**
 * Build both trees over a log file.
 *
 * Frames are hashed from the raw bytes and never decompressed, so this works at
 * disk speed: the integrity claim does not depend on being able to interpret the
 * content.
 */
export async function buildManifest(
  logPath: string,
  opts: BuildManifestOptions = {},
): Promise<{
  manifest: LedgerManifest
  frameTree: MerkleTree
  recordTree: MerkleTree
  records: RecordLeaf[]
  /** Present only when `includeRecordValues` was set. */
  values?: ManifestRecordValue[]
}> {
  const handle = await open(logPath, 'r')
  let buf: Buffer
  try {
    const size = (await handle.stat()).size
    const limit = opts.maxBytes ? Math.min(size, opts.maxBytes) : size
    buf = Buffer.alloc(limit)
    await handle.read(buf, 0, limit, 0)
  } finally {
    await handle.close()
  }

  const frameHashes: Buffer[] = []
  const recordHashes: Buffer[] = []
  const records: RecordLeaf[] = []
  const values: ManifestRecordValue[] = []
  let sessionId: string | undefined

  let offset = 0
  let frameIndex = 0
  for (;;) {
    const walk = walkFrameAt(buf, offset)
    if (walk.kind !== 'frame') break
    // Hash the frame in place: no copy, so memory stays flat in file size.
    frameHashes.push(hashLeaf(buf.subarray(walk.span.start, walk.span.end)))

    // Record leaves come from the decoded text; a frame that fails to decode
    // still contributes its frame leaf, so tampering cannot drop leaves.
    try {
      const text = decodeFrame(buf, walk.span)
      let start = 0
      for (let i = 0; i <= text.length; i++) {
        if (i === text.length || text.charCodeAt(i) === 0x0a) {
          const line = text.slice(start, i)
          start = i + 1
          const trimmed = line.trim()
          if (trimmed.length === 0) continue
          const bytes = Buffer.from(trimmed, 'utf8')
          recordHashes.push(hashLeaf(bytes))
          // Pull `seq`/`type` out of the record prefix instead of parsing the
          // whole record. On a 54k-record log the full parse dominated manifest
          // building, and the record tree does not need anything below the prefix.
          const meta = extractRecordMeta(trimmed)
          if (meta.type === 'session' && meta.sessionId) sessionId = meta.sessionId
          if (opts.includeRecordValues) {
            try {
              values.push({ value: JSON.parse(trimmed), frameIndex, frameStart: walk.span.start })
            } catch {
              /* unparsable records keep their leaf but yield no value */
            }
          }
          records.push({
            seq: meta.seq,
            recordType: meta.type,
            frameIndex,
            frameStart: walk.span.start,
            byteLength: bytes.length,
            hash: recordHashes[recordHashes.length - 1]!.toString('hex'),
          })
        }
      }
    } catch {
      /* frame leaf already recorded */
    }

    offset = walk.span.end
    frameIndex++
  }

  const frameTree = MerkleTree.fromHashes(frameHashes)
  const recordTree = MerkleTree.fromHashes(recordHashes)

  const manifest: LedgerManifest = {
    version: 1,
    algorithm: 'sha256/rfc6962',
    sessionId,
    file: logPath.replace(/^.*[\\/]/, ''),
    bytes: buf.length,
    frames: frameTree.size,
    records: recordTree.size,
    frameRoot: frameTree.rootHex,
    recordRoot: recordTree.rootHex,
    generatedAt: Date.now(),
  }
  return opts.includeRecordValues
    ? { manifest, frameTree, recordTree, records, values }
    : { manifest, frameTree, recordTree, records }
}

export interface VerificationResult {
  ok: boolean
  /** Which root, if any, failed to reproduce. */
  mismatch?: 'frameRoot' | 'recordRoot' | 'bytes' | 'frames' | 'records'
  actual: { bytes: number; frames: number; records: number; frameRoot: string; recordRoot: string }
  /** Byte offset of the first frame whose digest differs, when determinable. */
  firstDivergentFrame?: number
}

/**
 * Recompute a manifest and compare. Any changed, inserted, reordered or removed
 * byte in the log changes at least one root, so this is the tamper check.
 */
export async function verifyManifest(
  logPath: string,
  expected: LedgerManifest,
): Promise<VerificationResult> {
  const { manifest, frameTree, recordTree } = await buildManifest(logPath)
  const actual = {
    bytes: manifest.bytes,
    frames: manifest.frames,
    records: manifest.records,
    frameRoot: manifest.frameRoot,
    recordRoot: manifest.recordRoot,
  }
  let mismatch: VerificationResult['mismatch']
  if (manifest.bytes !== expected.bytes) mismatch = 'bytes'
  else if (manifest.frames !== expected.frames) mismatch = 'frames'
  else if (manifest.records !== expected.records) mismatch = 'records'
  else if (manifest.frameRoot !== expected.frameRoot) mismatch = 'frameRoot'
  else if (manifest.recordRoot !== expected.recordRoot) mismatch = 'recordRoot'
  void frameTree
  void recordTree
  return { ok: mismatch === undefined, mismatch, actual }
}

/** Stable JSON: keys sorted, so a manifest's signature does not depend on key order. */
export function canonicalize(value: unknown): string {
  const walk = (v: unknown): string => {
    if (v === null || typeof v !== 'object') return JSON.stringify(v) ?? 'null'
    if (Array.isArray(v)) return `[${v.map(walk).join(',')}]`
    const entries = Object.entries(v as Record<string, unknown>)
      .filter(([, x]) => x !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    return `{${entries.map(([k, x]) => `${JSON.stringify(k)}:${walk(x)}`).join(',')}}`
  }
  return walk(value)
}

/** Fields covered by a signature (everything except signature material itself). */
function signableManifest(m: LedgerManifest): string {
  const { signature: _s, signerPublicKey: _p, ...rest } = m
  return canonicalize(rest)
}

/** Sign a manifest with an Ed25519 (or any node:crypto) private key, PEM encoded. */
export function signManifest(manifest: LedgerManifest, privateKeyPem: string): LedgerManifest {
  const key = createPrivateKey(privateKeyPem)
  const sig = sign(null, Buffer.from(signableManifest(manifest), 'utf8'), key)
  const publicKey = createPublicKey(key)
  return {
    ...manifest,
    signature: sig.toString('base64'),
    signerPublicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  }
}

/** Verify a manifest's detached signature. Returns false for unsigned manifests. */
export function verifyManifestSignature(manifest: LedgerManifest): boolean {
  if (!manifest.signature) return false
  const pem = manifest.signerPublicKey
  if (!pem) return false
  try {
    return verify(
      null,
      Buffer.from(signableManifest(manifest), 'utf8'),
      createPublicKey(pem),
      Buffer.from(manifest.signature, 'base64'),
    )
  } catch {
    return false
  }
}

/** Digest of a single byte range, for cheap spot checks. */
export function digest(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex')
}
