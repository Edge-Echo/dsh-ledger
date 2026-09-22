/** SHA-256 of `0x00 || data`. Prefixed so leaves cannot be forged from nodes. */
export declare function hashLeaf(data: Buffer): Buffer;
/** SHA-256 of `0x01 || left || right`. */
export declare function hashNode(left: Buffer, right: Buffer): Buffer;
export interface ProofStep {
    hash: string;
    /** Where this sibling sits relative to the node being proven. */
    side: 'left' | 'right';
}
export interface MerkleProof {
    /** Index of the proven leaf (0-based). */
    leaf: number;
    /** Total leaf count of the tree the proof is against. */
    size: number;
    /** Sibling path, leaf level first. */
    path: ProofStep[];
}
export declare class MerkleTree {
    readonly size: number;
    readonly root: Buffer;
    /** Number of SHA-256 calls performed while building — reported for honesty about cost. */
    readonly hashes: number;
    private readonly levels;
    private constructor();
    /**
     * Build from already-hashed leaves. Passing digests rather than raw data lets
     * a caller hash in a streaming fashion and keep only 32 bytes per record.
     */
    static fromHashes(leaves: Buffer[]): MerkleTree;
    static fromLeaves(leaves: Buffer[]): MerkleTree;
    get rootHex(): string;
    /**
     * Inclusion proof for one leaf, in RFC 6962 shape. Recursive by design: the
     * tree shape must follow the same split rule as construction or a proof for a
     * non-power-of-two tree would verify against the wrong root.
     */
    prove(index: number): MerkleProof;
    /** Recompute the root from one leaf plus its proof. */
    static verify(proof: MerkleProof, leafHash: Buffer, root: Buffer): boolean;
    /** Convenience: verify raw leaf data (not a precomputed digest). */
    static verifyLeaf(proof: MerkleProof, leaf: Buffer, root: Buffer): boolean;
}
/** One leaf of a record tree: the exact bytes of a JSONL line. */
export interface RecordLeaf {
    /** DSH record sequence number, when the record carries one. */
    seq?: number;
    recordType?: string;
    frameIndex: number;
    frameStart: number;
    byteLength: number;
    hash: string;
}
/**
 * Read `type`, `seq` and (for the session header) `id` out of a record's leading
 * fields. DSH emits these first, so a bounded prefix scan is enough and full
 * `JSON.parse` of every record is avoided.
 */
export declare function extractRecordMeta(line: string, prefixLimit?: number): {
    type?: string;
    seq?: number;
    sessionId?: string;
};
export interface LedgerManifest {
    version: 1;
    algorithm: 'sha256/rfc6962';
    /** Session id parsed from the header record, when present. */
    sessionId?: string;
    /** Base name of the log file (full paths leak local layout). */
    file: string;
    bytes: number;
    frames: number;
    records: number;
    /** Merkle root over raw frame bytes. */
    frameRoot: string;
    /** Merkle root over record JSONL bytes. */
    recordRoot: string;
    generatedAt: number;
    /** Root of a signed manifest the signature covers; absent when unsigned. */
    signature?: string;
    signerPublicKey?: string;
}
export interface BuildManifestOptions {
    /** Cap on bytes read into memory at once. Defaults to the whole file. */
    maxBytes?: number;
    /**
     * Also return each record's parsed JSON value plus its provenance, so a caller
     * that needs both a manifest and a graph pays for one decode pass instead of
     * two. The record tree itself never needs the parse.
     */
    includeRecordValues?: boolean;
}
/** A parsed record plus where it came from — the shape the graph builder wants. */
export interface ManifestRecordValue {
    value: unknown;
    frameIndex: number;
    frameStart: number;
}
/**
 * Build both trees over a log file.
 *
 * Frames are hashed from the raw bytes and never decompressed, so this works at
 * disk speed: the integrity claim does not depend on being able to interpret the
 * content.
 */
export declare function buildManifest(logPath: string, opts?: BuildManifestOptions): Promise<{
    manifest: LedgerManifest;
    frameTree: MerkleTree;
    recordTree: MerkleTree;
    records: RecordLeaf[];
    /** Present only when `includeRecordValues` was set. */
    values?: ManifestRecordValue[];
}>;
export interface VerificationResult {
    ok: boolean;
    /** Which root, if any, failed to reproduce. */
    mismatch?: 'frameRoot' | 'recordRoot' | 'bytes' | 'frames' | 'records';
    actual: {
        bytes: number;
        frames: number;
        records: number;
        frameRoot: string;
        recordRoot: string;
    };
    /** Byte offset of the first frame whose digest differs, when determinable. */
    firstDivergentFrame?: number;
}
/**
 * Recompute a manifest and compare. Any changed, inserted, reordered or removed
 * byte in the log changes at least one root, so this is the tamper check.
 */
export declare function verifyManifest(logPath: string, expected: LedgerManifest): Promise<VerificationResult>;
/** Stable JSON: keys sorted, so a manifest's signature does not depend on key order. */
export declare function canonicalize(value: unknown): string;
/** Sign a manifest with an Ed25519 (or any node:crypto) private key, PEM encoded. */
export declare function signManifest(manifest: LedgerManifest, privateKeyPem: string): LedgerManifest;
/** Verify a manifest's detached signature. Returns false for unsigned manifests. */
export declare function verifyManifestSignature(manifest: LedgerManifest): boolean;
/** Digest of a single byte range, for cheap spot checks. */
export declare function digest(data: Buffer): string;
