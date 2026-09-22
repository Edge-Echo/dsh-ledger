import { type Diagnostic } from './reader.js';
import { type ExecutionGraph } from './graph.js';
import { type Effect, type EffectKind, type FileVersionChain } from './effects.js';
import { type LedgerManifest } from './merkle.js';
export * from './frames.js';
export * from './reader.js';
export * from './graph.js';
export * from './effects.js';
export * from './merkle.js';
export interface IngestStats {
    frames: number;
    records: number;
    bytes: number;
    ms: number;
    diagnostics: Diagnostic[];
    /** True when the log was read to its end (the writer may still append later). */
    complete: boolean;
}
export interface LedgerSnapshot {
    path: string;
    graph: ExecutionGraph;
    effects: Effect[];
    chains: Map<string, FileVersionChain>;
    effectSummary: Record<EffectKind, number>;
    ingest: IngestStats;
    /** Merkle roots over the same file, computed without decompressing. */
    integrity: {
        frameRoot: string;
        recordRoot: string;
        frames: number;
        records: number;
        ms: number;
    };
}
/**
 * Read a session log into a graph, its effects, and integrity roots.
 *
 * One pass: the record tree and the graph are built from a single decode, which
 * on a 21 MB / 34,729-frame log is the difference between decoding twice and
 * decoding once. Use `SessionLogTailer` directly for live tailing or when you
 * need to resume from a checkpoint.
 */
export declare function readLedger(logPath: string): Promise<LedgerSnapshot>;
/** Build the publishable evidence manifest for a log. */
export declare function attest(logPath: string): Promise<LedgerManifest>;
export interface SessionLogInfo {
    path: string;
    sessionId: string;
    /** Encoded working directory of the session, as DSH names it. */
    project: string;
    bytes: number;
    modifiedAt: number;
}
/** List session logs under a DSH home directory (default `~/.dsh`). */
export declare function findSessionLogs(home?: string): Promise<SessionLogInfo[]>;
/**
 * Render a ledger as text.
 *
 * Kept deliberately plain: this output is meant to be pasted into a PR, an
 * incident review, or a compliance note, and every number in it is traceable to
 * a record in the log.
 */
export declare function renderSummary(snapshot: LedgerSnapshot): string;
