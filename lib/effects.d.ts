import type { ToolCallEvent } from './graph.js';
export type EffectKind = 'read' | 'write' | 'edit' | 'search' | 'shell' | 'network' | 'delegation' | 'control' | 'unknown';
export type Fidelity = 'exact' | 'partial' | 'observed' | 'undecidable' | 'opaque';
export interface Effect {
    callId: string;
    toolName: string;
    turn: number;
    step: number;
    /** DSH record sequence number of the tool call. */
    seq?: number;
    time: number;
    /** Provenance of the record that produced this effect. */
    frameIndex: number;
    frameStart: number;
    kind: EffectKind;
    fidelity: Fidelity;
    /** Path as given by the model. */
    rawPath?: string;
    /** Path resolved against the session cwd, separators normalised. */
    path?: string;
    /** SHA-256 of the largest content fragment the log actually contains. */
    contentHash?: string;
    /** Byte length of that fragment. */
    bytes?: number;
    /** The shell command or query text, verbatim, for undecidable surfaces. */
    source?: string;
    /** Short human-readable summary. */
    detail: string;
    /** True when this effect cannot be fully reconstructed from the log. */
    undecidable: boolean;
}
/** Normalise a path for grouping: resolve against cwd, unify separators. */
export declare function resolvePath(raw: string, cwd?: string): string;
/**
 * Extract effects from one tool call.
 *
 * Covers the tool surface DSH actually ships; anything else is reported as
 * `unknown` rather than silently dropped, so a new tool shows up as a gap in the
 * ledger instead of an invisible one.
 */
export declare function effectsOf(call: ToolCallEvent, cwd?: string): Effect[];
/** One step in the history of a path. */
export interface VersionStep {
    seq?: number;
    time: number;
    callId: string;
    toolName: string;
    kind: EffectKind;
    fidelity: Fidelity;
    contentHash?: string;
    bytes?: number;
    detail: string;
}
export interface FileVersionChain {
    path: string;
    /** Ordered oldest first. */
    steps: VersionStep[];
    /** True when the session created the file (first effect is a whole-file write). */
    created: boolean;
    /** True when the agent edited a file it never wrote — it pre-existed. */
    preexisting: boolean;
    /** SHA-256 of the last whole-file content the log contains, when one exists. */
    lastExactHash?: string;
    /** True when a shell command ran between two recorded versions of this path. */
    contaminated: boolean;
    /** How many shell effects fell inside the chain's record-sequence window. */
    shellsInWindow: number;
}
/**
 * Group effects into per-path version chains.
 *
 * `contaminated` is the load-bearing field here. A shell command can create,
 * overwrite or delete anything, so a file version is only clean if *no* shell
 * command ran between two recorded versions of it. On a real session that marks
 * most chains contaminated — because it is true. Reporting it as clean would turn
 * an audit trail into a plausible story, which is the failure mode this whole
 * library exists to avoid.
 */
export declare function buildVersionChains(effects: Effect[]): Map<string, FileVersionChain>;
/** Aggregate counts per effect kind, for reporting. */
export declare function summarizeEffects(effects: Effect[]): Record<EffectKind, number>;
