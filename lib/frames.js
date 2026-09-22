// dsh-ledger — zstd frame structure walking.
//
// DSH session logs are append-only `.jsonl.zstd`: every append is an independent
// zstd frame, so one file is a concatenation of frames. Node's zlib decodes only
// the first frame and its stream API rejects the rest ("Unknown frame
// descriptor"); DSH itself works around this with a private zstd handle plus a
// koffi FFI fallback.
//
// This module does it differently — and better for our purposes: it parses the
// frame structure itself (RFC 8878) to find exact frame boundaries without
// decoding. That buys three properties the decode-and-guess approaches cannot
// give:
//
//   1. **Incremental** — a reader can stop at the last complete frame and resume
//      from a byte offset later, instead of re-decoding the whole file.
//   2. **Bounded memory** — one frame is decoded at a time; the file is never
//      held in memory.
//   3. **Crash-safe** — a half-written frame at the tail is held back (not lost,
//      not misparsed), and a corrupt frame in the middle is skipped by resyncing
//      on the next frame magic instead of aborting the read.
//
// Frame layout (RFC 8878):
//
//   Magic_Number(4, LE 0xFD2FB528)
//   Frame_Header(2..14)
//     Frame_Header_Descriptor(1): bits7-6 FCS_flag, bit5 Single_Segment,
//       bit4 unused, bit3 reserved, bit2 Content_Checksum, bits1-0 DictID_flag
//     Window_Descriptor(0..1): present iff Single_Segment == 0
//     Dictionary_ID(0..4): 0/1/2/4 bytes per DictID_flag
//     Frame_Content_Size(0/1/2/4/8): per FCS_flag (2-byte form adds 256)
//   Data_Blocks: Block_Header(3, LE): bit0 Last_Block, bits1-2 Block_Type,
//     bits3-23 Block_Size; Raw/Compressed carry Block_Size bytes, RLE carries 1
//   Content_Checksum(0..4): present iff Content_Checksum flag set
//
// Skippable frames (magic 0x184D2A50..0x184D2A5F) are also walked and reported.
import { zstdDecompressSync } from 'node:zlib';
/** Standard zstd frame magic, little-endian on disk (28 B5 2F FD). */
export const ZSTD_MAGIC = 0xfd2fb528;
/** Inclusive range of skippable-frame magics. */
export const SKIPPABLE_MAGIC_MIN = 0x184d2a50;
export const SKIPPABLE_MAGIC_MAX = 0x184d2a5f;
const BLOCK_TYPE_RAW = 0;
const BLOCK_TYPE_RLE = 1;
const BLOCK_TYPE_COMPRESSED = 2;
const BLOCK_TYPE_RESERVED = 3;
function readU24LE(buf, at) {
    return buf[at] | (buf[at + 1] << 8) | (buf[at + 2] << 16);
}
/**
 * Walk one frame starting at `offset`, using only its structure — no decode.
 *
 * Returns `incomplete` (rather than throwing) when the buffer ends inside the
 * frame, which is the normal case for a log whose writer is mid-append.
 */
export function walkFrameAt(buf, offset) {
    if (offset >= buf.length)
        return { kind: 'eof' };
    // ── skippable frame ──────────────────────────────────────────────────────
    if (buf.length - offset >= 8) {
        const magic = buf.readUInt32LE(offset);
        if (magic >= SKIPPABLE_MAGIC_MIN && magic <= SKIPPABLE_MAGIC_MAX) {
            const size = buf.readUInt32LE(offset + 4);
            const end = offset + 8 + size;
            if (end > buf.length)
                return { kind: 'incomplete', start: offset, needBytes: end - buf.length };
            return { kind: 'frame', span: { start: offset, end, skippable: true, blocks: 0 } };
        }
    }
    else if (buf.length - offset < 4) {
        return { kind: 'incomplete', start: offset, needBytes: 4 - (buf.length - offset) };
    }
    // ── standard frame ───────────────────────────────────────────────────────
    if (buf.readUInt32LE(offset) !== ZSTD_MAGIC) {
        return { kind: 'corrupt', start: offset, reason: 'bad magic' };
    }
    if (buf.length - offset < 5)
        return { kind: 'incomplete', start: offset, needBytes: 5 - (buf.length - offset) };
    const descriptor = buf[offset + 4];
    if ((descriptor & 0x08) !== 0) {
        return { kind: 'corrupt', start: offset, reason: 'reserved bit set in frame header descriptor' };
    }
    const fcsFlag = (descriptor >> 6) & 0x03;
    const singleSegment = (descriptor & 0x20) !== 0;
    const hasChecksum = (descriptor & 0x04) !== 0;
    const dictIdFlag = descriptor & 0x03;
    // Frame_Content_Size field width, per RFC 8878 table 5.
    const fcsWidth = fcsFlag === 0 ? (singleSegment ? 1 : 0) : fcsFlag === 1 ? 2 : fcsFlag === 2 ? 4 : 8;
    const dictIdWidth = dictIdFlag === 0 ? 0 : dictIdFlag === 1 ? 1 : dictIdFlag === 2 ? 2 : 4;
    const windowWidth = singleSegment ? 0 : 1;
    const headerEnd = offset + 5 + windowWidth + dictIdWidth + fcsWidth;
    if (headerEnd > buf.length)
        return { kind: 'incomplete', start: offset, needBytes: headerEnd - buf.length };
    let contentSize;
    if (fcsWidth === 1) {
        contentSize = buf[offset + 5 + windowWidth + dictIdWidth];
    }
    else if (fcsWidth === 2) {
        contentSize = buf.readUInt16LE(offset + 5 + windowWidth + dictIdWidth) + 256;
    }
    else if (fcsWidth === 4) {
        contentSize = buf.readUInt32LE(offset + 5 + windowWidth + dictIdWidth);
    }
    else if (fcsWidth === 8) {
        const lo = buf.readUInt32LE(offset + 5 + windowWidth + dictIdWidth);
        const hi = buf.readUInt32LE(offset + 5 + windowWidth + dictIdWidth + 4);
        if (hi !== 0)
            contentSize = undefined; // beyond Number.MAX_SAFE_INTEGER for our purposes
        else
            contentSize = lo;
    }
    // ── data blocks ──────────────────────────────────────────────────────────
    let cursor = headerEnd;
    let blocks = 0;
    for (;;) {
        if (cursor + 3 > buf.length)
            return { kind: 'incomplete', start: offset, needBytes: cursor + 3 - buf.length };
        const header = readU24LE(buf, cursor);
        const lastBlock = (header & 0x01) !== 0;
        const blockType = (header >> 1) & 0x03;
        const blockSize = header >>> 3;
        cursor += 3;
        if (blockType === BLOCK_TYPE_RESERVED) {
            return { kind: 'corrupt', start: offset, reason: 'reserved block type' };
        }
        const payload = blockType === BLOCK_TYPE_RLE ? 1 : blockSize;
        if (cursor + payload > buf.length) {
            return { kind: 'incomplete', start: offset, needBytes: cursor + payload - buf.length };
        }
        cursor += payload;
        blocks++;
        if (lastBlock)
            break;
        if (blocks > 1_000_000)
            return { kind: 'corrupt', start: offset, reason: 'implausible block count' };
    }
    if (hasChecksum) {
        if (cursor + 4 > buf.length)
            return { kind: 'incomplete', start: offset, needBytes: cursor + 4 - buf.length };
        cursor += 4;
    }
    return { kind: 'frame', span: { start: offset, end: cursor, contentSize, skippable: false, blocks } };
}
/** Decode one non-skippable frame slice; skippable frames decode to empty text. */
export function decodeFrame(buf, span) {
    if (span.skippable)
        return '';
    return zstdDecompressSync(buf.subarray(span.start, span.end)).toString('utf8');
}
const MAGIC_BYTES = Buffer.from([0x28, 0xb5, 0x2f, 0xfd]);
/**
 * Find the next plausible frame boundary at or after `from`.
 * Used to resync after a corrupt region.
 */
export function findNextFrameMagic(buf, from) {
    return buf.indexOf(MAGIC_BYTES, from);
}
