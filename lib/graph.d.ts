import type { RawRecord } from './reader.js';
import { type Effect } from './effects.js';
export interface SessionHeader {
    id?: string;
    createdAt?: number;
    cwd?: string;
    delegationDepth?: number;
    agentPreset?: string;
}
export interface TokenUsage {
    inputTokens: number;
    outputTokens: number;
    cacheReadTokens: number;
    reasoningTokens: number;
    /** Number of usage-bearing assistant messages aggregated here. */
    messages: number;
}
export declare const emptyUsage: () => TokenUsage;
export interface ToolCallEvent {
    callId: string;
    name: string;
    /** Parsed arguments; `{}` when the log's argument string was empty/unparsable. */
    arguments: Record<string, unknown>;
    /** Raw argument string exactly as logged. */
    rawArguments: string;
    turn: number;
    step: number;
    seq?: number;
    time: number;
    frameIndex: number;
    frameStart: number;
}
export interface ToolResultEvent {
    callId: string;
    isError: boolean;
    /** Flattened text of every text block in the result. */
    text: string;
    textBytes: number;
    time: number;
    seq?: number;
    frameIndex: number;
}
export interface ToolCallRecord {
    call: ToolCallEvent;
    result?: ToolResultEvent;
    /** Wall-clock duration when both call and result are present. */
    durationMs?: number;
    effects: Effect[];
}
export interface StepNode {
    turn: number;
    step: number;
    startedAt?: number;
    endedAt?: number;
    durationMs?: number;
    /** True when no step/end record was seen for this step. */
    unterminated: boolean;
    calls: string[];
}
export interface TurnNode {
    turn: number;
    startedAt?: number;
    endedAt?: number;
    durationMs?: number;
    /** `reason.kind` from turn/end, e.g. `completed`, `aborted`. */
    endReason?: string;
    unterminated: boolean;
    steps: StepNode[];
    usage: TokenUsage;
    calls: string[];
    errors: number;
}
export type AnomalyKind = 'llm-retry' | 'tool-error' | 'compaction' | 'turn-aborted' | 'approval-asked' | 'approval-denied' | 'permission-change' | 'unpaired-tool-call' | 'orphan-tool-result';
export interface Anomaly {
    kind: AnomalyKind;
    turn?: number;
    step?: number;
    time?: number;
    seq?: number;
    /** Record index in the input array, for provenance back to the file. */
    recordIndex: number;
    frameIndex: number;
    frameStart: number;
    detail: string;
    data?: Record<string, unknown>;
}
export interface GraphStats {
    records: number;
    parsed: number;
    unparsable: number;
    byType: Record<string, number>;
    streamingRecords: number;
    /** Assistant reasoning characters seen in streaming deltas (never retained). */
    reasoningChars: number;
    toolCalls: number;
    toolResults: number;
    paired: number;
}
export interface ExecutionGraph {
    session: SessionHeader;
    /** Governance as the session started. */
    governance: {
        permissionPreset?: string;
        sandboxMode?: string;
        approvalPolicy?: string;
    };
    /** Governance as of the last record — differs when a preset changed mid-session. */
    governanceFinal: {
        permissionPreset?: string;
        sandboxMode?: string;
        approvalPolicy?: string;
    };
    turns: TurnNode[];
    calls: ToolCallRecord[];
    callIndex: Map<string, number>;
    usage: TokenUsage;
    usageByModel: Map<string, TokenUsage>;
    anomalies: Anomaly[];
    /** Assistant text blocks, in order. */
    assistantTexts: {
        turn: number;
        step: number;
        text: string;
        id?: string;
    }[];
    userMessages: {
        turn: number;
        text: string;
        time: number;
    }[];
    stats: GraphStats;
}
/**
 * Build an execution graph from parsed log records.
 *
 * Records arrive in file order, which the log guarantees (append-only), so the
 * graph is built in a single pass with no sorting.
 */
export declare function buildGraph(records: RawRecord[]): ExecutionGraph;
