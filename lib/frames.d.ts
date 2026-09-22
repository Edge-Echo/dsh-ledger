/** Standard zstd frame magic, little-endian on disk (28 B5 2F FD). */
export declare const ZSTD_MAGIC = 4247762216;
/** Inclusive range of skippable-frame magics. */
export declare const SKIPPABLE_MAGIC_MIN = 407710288;
export declare const SKIPPABLE_MAGIC_MAX = 407710303;
/** Byte range of one frame within a buffer. */
export interface FrameSpan {
    /** Offset of the frame's first magic byte. */
    start: number;
    /** Offset just past the frame's last byte (checksum included). */
    end: number;
    /** Declared decompressed size, when the header carries it. */
    contentSize?: number;
    /** True when this is a skippable frame (no payload semantics). */
    skippable: boolean;
    /** Number of data blocks walked (0 for skippable). */
    blocks: number;
}
/** Outcome of walking one frame at an offset. */
export type FrameWalk = {
    kind: 'frame';
    span: FrameSpan;
}
/** The bytes present are a valid prefix of a frame — the writer may still be appending. */
 | {
    kind: 'incomplete';
    start: number;
    needBytes: number;
}
/** The bytes at `start` cannot begin a frame. */
 | {
    kind: 'corrupt';
    start: number;
    reason: string;
}
/** No bytes available at `start`. */
 | {
    kind: 'eof';
};
/**
 * Walk one frame starting at `offset`, using only its structure — no decode.
 *
 * Returns `incomplete` (rather than throwing) when the buffer ends inside the
 * frame, which is the normal case for a log whose writer is mid-append.
 */
export declare function walkFrameAt(buf: Buffer, offset: number): FrameWalk;
/** A resynchronisation or structural problem encountered while reading. */
export interface FrameDiagnostic {
    /** Byte offset where the problem was observed. */
    offset: number;
    kind: 'corrupt' | 'trailing-garbage';
    detail: string;
    /** Bytes skipped to reach the next frame magic. */
    skippedBytes: number;
}
/** Decode one non-skippable frame slice; skippable frames decode to empty text. */
export declare function decodeFrame(buf: Buffer, span: FrameSpan): string;
/**
 * Find the next plausible frame boundary at or after `from`.
 * Used to resync after a corrupt region.
 */
export declare function findNextFrameMagic(buf: Buffer, from: number): number;
