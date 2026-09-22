// dsh-ledger — public API.
//
// Five layers, each useful on its own:
//
//   frames.ts   zstd frame structure walker (no decode needed for boundaries)
//   reader.ts   incremental, crash-safe tailer with a resumable checkpoint
//   graph.ts    records -> turns, steps, tool calls, token usage, anomalies
//   effects.ts  tool calls -> typed effects with explicit fidelity
//   merkle.ts   RFC 6962 integrity trees, inclusion proofs, signed manifests
//
// The facade below is the short path: point it at a DSH session log and get a
// ledger you can audit, or a manifest you can publish and verify later.
import { readdir, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { buildGraph } from './graph.js';
import { buildVersionChains, summarizeEffects, } from './effects.js';
import { buildManifest } from './merkle.js';
export * from './frames.js';
export * from './reader.js';
export * from './graph.js';
export * from './effects.js';
export * from './merkle.js';
/**
 * Read a session log into a graph, its effects, and integrity roots.
 *
 * One pass: the record tree and the graph are built from a single decode, which
 * on a 21 MB / 34,729-frame log is the difference between decoding twice and
 * decoding once. Use `SessionLogTailer` directly for live tailing or when you
 * need to resume from a checkpoint.
 */
export async function readLedger(logPath) {
    const started = Date.now();
    const stats = { frames: 0, records: 0, bytes: 0, pendingBytes: 0, diagnostics: [] };
    const integrityStarted = Date.now();
    const { manifest, values, records } = await buildManifest(logPath, { includeRecordValues: true });
    const integrityMs = Date.now() - integrityStarted;
    const raw = (values ?? []).map((v) => ({
        value: v.value,
        frameIndex: v.frameIndex,
        frameStart: v.frameStart,
    }));
    stats.frames = manifest.frames;
    stats.records = records.length;
    stats.bytes = manifest.bytes;
    const graph = buildGraph(raw);
    const effects = graph.calls.flatMap((c) => c.effects);
    return {
        path: logPath,
        graph,
        effects,
        chains: buildVersionChains(effects),
        effectSummary: summarizeEffects(effects),
        ingest: {
            frames: stats.frames,
            records: stats.records,
            bytes: stats.bytes,
            ms: Date.now() - started,
            diagnostics: stats.diagnostics,
            complete: true,
        },
        integrity: {
            frameRoot: manifest.frameRoot,
            recordRoot: manifest.recordRoot,
            frames: manifest.frames,
            records: manifest.records,
            ms: integrityMs,
        },
    };
}
/** Build the publishable evidence manifest for a log. */
export async function attest(logPath) {
    const { manifest } = await buildManifest(logPath);
    return manifest;
}
/** List session logs under a DSH home directory (default `~/.dsh`). */
export async function findSessionLogs(home = process.env.DSH_HOME ?? join(homedir(), '.dsh')) {
    const root = join(home, 'sessions');
    const out = [];
    let projects;
    try {
        projects = await readdir(root);
    }
    catch {
        return out;
    }
    for (const project of projects) {
        let sessions;
        try {
            sessions = await readdir(join(root, project));
        }
        catch {
            continue;
        }
        for (const session of sessions) {
            const path = join(root, project, session, 'session.jsonl.zstd');
            try {
                const st = await stat(path);
                if (!st.isFile())
                    continue;
                out.push({
                    path,
                    sessionId: session,
                    project,
                    bytes: st.size,
                    modifiedAt: st.mtimeMs,
                });
            }
            catch {
                /* not a session directory */
            }
        }
    }
    return out.sort((a, b) => b.modifiedAt - a.modifiedAt);
}
/**
 * Render a ledger as text.
 *
 * Kept deliberately plain: this output is meant to be pasted into a PR, an
 * incident review, or a compliance note, and every number in it is traceable to
 * a record in the log.
 */
export function renderSummary(snapshot) {
    const { graph, effectSummary, chains, ingest, integrity } = snapshot;
    const lines = [];
    const session = graph.session;
    lines.push(`session   ${session.id ?? '(unknown)'}`);
    if (session.cwd)
        lines.push(`cwd       ${session.cwd}`);
    if (session.agentPreset)
        lines.push(`preset    ${session.agentPreset}`);
    const gov = graph.governance;
    lines.push(`sandbox   ${gov.sandboxMode ?? '?'}  approval ${gov.approvalPolicy ?? '?'}  permission ${gov.permissionPreset ?? '?'}`);
    lines.push(`log       ${ingest.frames} frames, ${ingest.records} records, ${ingest.bytes} bytes in ${ingest.ms}ms` +
        ` (${ingest.diagnostics.length} diagnostics)`);
    lines.push(`turns     ${graph.turns.length}`);
    lines.push(`usage     input ${graph.usage.inputTokens} output ${graph.usage.outputTokens} ` +
        `cache-read ${graph.usage.cacheReadTokens} reasoning ${graph.usage.reasoningTokens}`);
    lines.push('');
    lines.push('effects');
    for (const [kind, count] of Object.entries(effectSummary).sort((a, b) => b[1] - a[1])) {
        if (count > 0)
            lines.push(`  ${kind.padEnd(11)} ${count}`);
    }
    const undecidable = snapshot.effects.filter((e) => e.undecidable).length;
    lines.push(`  ${'undecidable'.padEnd(11)} ${undecidable} effect(s) cannot be reconstructed from the log`);
    lines.push('');
    lines.push(`files touched (${chains.size})`);
    const sorted = [...chains.values()].sort((a, b) => b.steps.length - a.steps.length);
    for (const chain of sorted.slice(0, 15)) {
        const flag = chain.contaminated ? ' [shell in scope]' : '';
        lines.push(`  ${chain.created ? 'new  ' : chain.preexisting ? 'pre  ' : 'mod  '} ${chain.steps.length}x ${chain.path}${flag}`);
    }
    if (sorted.length > 15)
        lines.push(`  … and ${sorted.length - 15} more`);
    if (graph.anomalies.length > 0) {
        lines.push('');
        lines.push(`anomalies (${graph.anomalies.length})`);
        for (const a of graph.anomalies.slice(0, 15)) {
            lines.push(`  ${a.kind.padEnd(20)} ${a.detail}`);
        }
        if (graph.anomalies.length > 15)
            lines.push(`  … and ${graph.anomalies.length - 15} more`);
    }
    lines.push('');
    lines.push(`integrity frameRoot  ${integrity.frameRoot}`);
    lines.push(`          recordRoot ${integrity.recordRoot}`);
    return lines.join('\n');
}
