/** A record with provenance: where in the file it came from. */
export interface RawRecord {
    value: unknown;
    /** Zero-based index of the frame that carried this record. */
    frameIndex: number;
    /** Absolute byte offset of that frame's magic number. */
    frameStart: number;
}
export type DiagnosticKind = 'corrupt' | 'oversize-frame' | 'bad-json';
export interface Diagnostic {
    kind: DiagnosticKind;
    /** Absolute byte offset where the problem was observed. */
    offset: number;
    detail: string;
    /** Bytes skipped while resynchronising (0 when nothing was skipped). */
    skippedBytes: number;
}
export interface TailBatch {
    records: RawRecord[];
    /** Frames fully consumed during this call. */
    frames: number;
    /** Absolute offset just past the last complete frame — persist this. */
    bytesConsumed: number;
    /** Bytes held back as an incomplete frame (or an incomplete record line). */
    pendingBytes: number;
    diagnostics: Diagnostic[];
    /**
     * True when reading reached the current end of the file. Callers stop here
     * when draining; a live tailer calls `poll()` again later, since the writer
     * may have appended more. A partial tail frame does not make this false — it
     * is simply held back until the writer completes it.
     */
    atEnd: boolean;
}
export interface TailerOptions {
    /** Read granularity in bytes. Default 1 MiB. */
    chunkBytes?: number;
    /**
     * Refuse to hold more than this many bytes for a single incomplete frame.
     * Exceeding it means the "frame" is really a corrupt region, so the tailer
     * resynchronises instead of growing without bound. Default 64 MiB.
     */
    maxFrameBytes?: number;
    /**
     * How many bytes to read ahead before consuming frames, as a multiple of
     * `chunkBytes`. Caps the memory a single `poll()` can allocate. Default 4.
     */
    readAheadChunks?: number;
    /** Absolute byte offset to start reading from (a previous checkpoint). */
    from?: number;
}
export interface TailerStats {
    frames: number;
    records: number;
    /** Durable checkpoint: offset to resume from. */
    bytesConsumed: number;
    /** Bytes read from disk in total (may exceed bytesConsumed after corruption). */
    bytesRead: number;
    /** Bytes currently held back. */
    pendingBytes: number;
    /** Problems seen so far, in file order. */
    diagnostics: Diagnostic[];
}
export declare class SessionLogTailer {
    readonly path: string;
    private handle;
    private readonly chunkBytes;
    private readonly maxFrameBytes;
    private readonly readAhead;
    /** Unconsumed bytes; carry[0] sits at absolute offset `carryOffset`. */
    private carry;
    private carryOffset;
    /** Next byte to read from the file. */
    private readPos;
    /** Trailing partial line from the previous frame. */
    private lineCarry;
    /** Checkpoint: resume offset. */
    private consumed;
    private frames;
    private recordCount;
    private bytesRead;
    private allDiagnostics;
    private pendingRecords;
    private reportedFrames;
    constructor(path: string, opts?: TailerOptions);
    open(): Promise<void>;
    close(): Promise<void>;
    get stats(): TailerStats;
    /**
     * Read whatever is new and complete. Safe to call repeatedly against a live
     * log, and safe to call after a crash: resumes from the checkpoint.
     *
     * Reads at most `readAheadChunks * chunkBytes` before consuming, so a large
     * log streams through in bounded memory. Call until `atEnd` for a full sweep.
     */
    poll(): Promise<TailBatch>;
    /** Drain the whole file, however many polls that takes. */
    drain(): Promise<TailBatch>;
    /** Skip forward to the next frame magic after a structural problem. */
    private resync;
    /**
     * Decode one complete frame, split it into JSONL records, and advance the
     * checkpoint. Called only with a structurally valid span.
     */
    private consumeFrame;
    private compact;
    /** Discard all state and start over, e.g. when a checkpoint is stale. */
    rewind(from?: number): Promise<void>;
}
