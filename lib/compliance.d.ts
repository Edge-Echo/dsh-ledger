import type { Effect, EffectKind } from './effects.js';
import type { ExecutionGraph } from './graph.js';
/** The schema id of the format this module emits. */
export declare const COMPLIANCE_SCHEMA = "dsh-audit-trail/compliance/1";
/** The canonicalisation prefix used inside the hash chain. */
export declare const CANONICAL_PREFIX = "dsh-audit-trail/canonical/1";
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
/** Ordered least to most severe, matching the upstream ladder. */
export declare const SEVERITIES: readonly Severity[];
export declare const severityRank: (s: Severity) => number;
/** The `kind` values the upstream schema defines. */
export declare const AUDIT_KINDS: readonly ["session_live", "turn_start", "turn_end", "step_start", "step_end", "user_message", "assistant_message", "assistant_chunk", "todo_update", "request_header", "request_context", "tool_call", "tool_result", "tool_dispatch", "tool_registered"];
export type AuditKind = (typeof AUDIT_KINDS)[number];
/** One payload row of the compliance format, in upstream field order. */
export interface CompliancePayload {
    sessionId: string;
    ts: number;
    kind: AuditKind;
    turn: number | null;
    step: number | null;
    toolName: string | null;
    callId: string | null;
    argsDigest: string | null;
    status: string | null;
    durationMs: number | null;
    severity: Severity;
    flags: string[];
    summary: string;
    detail: string | null;
    filesRead: string[];
    filesWritten: string[];
    network: string[];
    actor: string | null;
    sourceType: string;
    sourceSeq: number | null;
}
export interface ComplianceLine {
    recordId: number;
    prevHash: string | null;
    payload: CompliancePayload;
    hashSelf: string;
}
/**
 * Deterministic JSON: object keys sorted lexicographically, arrays keep order.
 * Matches upstream `stableStringify`, which the hash chain depends on.
 */
export declare function stableStringify(value: unknown): string;
/**
 * The exact field vector the upstream hash covers. It is an *array*, and its order
 * is part of the format — a reordering silently changes every downstream hash, so
 * this is copied field for field rather than derived.
 */
export declare function canonicalRecordFields(p: CompliancePayload): unknown[];
/** The canonical text of one record, as hashed. */
export declare function canonicalRecord(p: CompliancePayload): string;
/** Hash of one record given the previous record's hash. */
export declare function chainHash(prevHash: string | null, p: CompliancePayload): string;
/** Pull the paths a command names, best effort — used only to pick a severity. */
export declare function commandTargets(command: string): string[];
export interface RiskAssessment {
    severity: Severity;
    flags: string[];
}
/**
 * Score one effect. This is the part of the compliance export that the ledger
 * contributes beyond what a plain recorder can see: it knows the fidelity of each
 * effect, so it can be loud where the log is decisive and explicit where it is not.
 */
export declare function assessEffect(effect: Effect, cwd?: string): RiskAssessment;
/**
 * Convert a graph into compliance payloads.
 *
 * Records are emitted in log order so the resulting chain is also a timeline. The
 * ledger's own richer facts (effect fidelity, version chains, anomalies) go to the
 * sidecar rather than being forced into a kind that does not describe them.
 */
export declare function toCompliancePayloads(graph: ExecutionGraph): CompliancePayload[];
/**
 * The hash of one JSONL line.
 *
 * This is deliberately **not** `chainHash`. The upstream package uses two different
 * constructions: `chainHash` (+`canonicalRecord`) chains the SQLite audit store,
 * while the compliance JSONL is chained over a `{recordId, prevHash, payload}`
 * signature object. Using the store primitive in a document produces a file that
 * looks right and that the reference verifier rejects — which is exactly what the
 * conformance test caught.
 */
export declare function documentHash(prevHash: string, line: {
    recordId: number;
    prevHash: string | null;
    payload: CompliancePayload;
}): string;
/**
 * Build the chained JSONL document (header line + one record per line).
 *
 * `hashSelf` must not be part of the hashed object, so the signature is hashed
 * before the emitted line is assembled.
 */
export declare function complianceJsonl(payloads: CompliancePayload[], opts?: {
    hashChain?: boolean;
}): string;
export interface ChainVerification {
    valid: boolean;
    lines: number;
    records: number;
    issues: string[];
    /** Highest severity seen, useful for a quick risk read of a pack. */
    maxSeverity?: Severity;
}
/** Independent verification of a chained JSONL document, without upstream installed. */
export declare function verifyComplianceChain(text: string): ChainVerification;
/**
 * Verify using the upstream package when it is installed, so a third party gets the
 * verdict from the reference implementation rather than from this one.
 */
export declare function verifyComplianceWithUpstream(text: string): Promise<ChainVerification & {
    verifier: 'dsh-audit-trail' | 'dsh-ledger';
}>;
/** Counts by severity, for reporting. */
export declare function severityHistogram(payloads: CompliancePayload[]): Record<Severity, number>;
/** Effect-kind totals, reused by the CLI's classify command. */
export declare function effectKindTotals(effects: Effect[]): Partial<Record<EffectKind, number>>;
