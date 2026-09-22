// dsh-ledger — effect attribution.
//
// The question this module answers is the one an audit actually asks: *what did
// the agent do to the machine?* Each tool call is turned into typed effects, and
// — just as important — every effect carries an explicit **fidelity**:
//
//   exact        the full content is in the log (a `write` with its `content`)
//   partial      only a fragment is in the log (an `edit` carries the replaced
//                and replacement text, not the surrounding file)
//   observed     the call proves the path was touched, not what it held
//   undecidable  the effect surface cannot be reconstructed from the log at all
//
// That last one is not a cop-out, it is the honest core of the design. A shell
// command (`pwsh`, 650 of 1860 calls in the reference session) can create, delete
// or overwrite anything; inferring its file effects from the command string would
// be guesswork dressed as evidence. dsh-ledger therefore records the command
// verbatim, marks the effect `undecidable`, and lets the integrity layer prove
// that the *record* of the command is untampered — which is the claim that can
// actually be defended.
import { hash as sha256 } from 'node:crypto'
import type { ToolCallEvent } from './graph.js'

export type EffectKind =
  | 'read'
  | 'write'
  | 'edit'
  | 'search'
  | 'shell'
  | 'network'
  | 'delegation'
  | 'control'
  | 'unknown'

export type Fidelity = 'exact' | 'partial' | 'observed' | 'undecidable' | 'opaque'

export interface Effect {
  callId: string
  toolName: string
  turn: number
  step: number
  /** DSH record sequence number of the tool call. */
  seq?: number
  time: number
  /** Provenance of the record that produced this effect. */
  frameIndex: number
  frameStart: number
  kind: EffectKind
  fidelity: Fidelity
  /** Path as given by the model. */
  rawPath?: string
  /** Path resolved against the session cwd, separators normalised. */
  path?: string
  /** SHA-256 of the largest content fragment the log actually contains. */
  contentHash?: string
  /** Byte length of that fragment. */
  bytes?: number
  /** The shell command or query text, verbatim, for undecidable surfaces. */
  source?: string
  /** Short human-readable summary. */
  detail: string
  /** True when this effect cannot be fully reconstructed from the log. */
  undecidable: boolean
}

/** Normalise a path for grouping: resolve against cwd, unify separators. */
export function resolvePath(raw: string, cwd?: string): string {
  let p = raw.trim().replace(/^"|"$/g, '')
  if (!p) return p
  if (/^[a-zA-Z]:[\\/]/.test(p) || p.startsWith('\\\\') || p.startsWith('/')) {
    return p.replace(/\//g, '\\')
  }
  if (!cwd) return p.replace(/\//g, '\\')
  return `${cwd.replace(/[\\/]+$/, '')}\\${p.replace(/\//g, '\\')}`
}

const sha256Hex = (text: string): string => sha256('sha256', Buffer.from(text, 'utf8'), 'hex')

const byteLen = (text: string): number => Buffer.byteLength(text, 'utf8')

function argString(args: Record<string, unknown>, ...keys: string[]): string | undefined {
  for (const key of keys) {
    const v = args[key]
    if (typeof v === 'string' && v.length > 0) return v
  }
  return undefined
}

/**
 * Extract effects from one tool call.
 *
 * Covers the tool surface DSH actually ships; anything else is reported as
 * `unknown` rather than silently dropped, so a new tool shows up as a gap in the
 * ledger instead of an invisible one.
 */
export function effectsOf(call: ToolCallEvent, cwd?: string): Effect[] {
  const args = (call.arguments ?? {}) as Record<string, unknown>
  const base = {
    callId: call.callId,
    toolName: call.name,
    turn: call.turn,
    step: call.step,
    seq: call.seq,
    time: call.time,
    frameIndex: call.frameIndex,
    frameStart: call.frameStart,
  }
  const name = call.name
  const one = (e: Omit<Effect, keyof typeof base>): Effect[] => [{ ...base, ...e }]

  switch (name) {
    case 'write': {
      const raw = argString(args, 'file_path', 'path', 'filePath')
      const content = argString(args, 'content') ?? ''
      if (!raw) return one({ kind: 'unknown', fidelity: 'opaque', detail: 'write without a path', undecidable: true })
      return one({
        kind: 'write',
        fidelity: 'exact',
        rawPath: raw,
        path: resolvePath(raw, cwd),
        contentHash: sha256Hex(content),
        bytes: byteLen(content),
        detail: `wrote ${byteLen(content)} bytes`,
        undecidable: false,
      })
    }
    case 'edit': {
      const raw = argString(args, 'file_path', 'path', 'filePath')
      const oldText = argString(args, 'old_string', 'oldText') ?? ''
      const newText = argString(args, 'new_string', 'newText') ?? ''
      if (!raw) return one({ kind: 'unknown', fidelity: 'opaque', detail: 'edit without a path', undecidable: true })
      const replaceAll = args.replace_all === true || args.replaceAll === true
      return one({
        kind: 'edit',
        fidelity: 'partial',
        rawPath: raw,
        path: resolvePath(raw, cwd),
        // The hash covers only the replacement fragment: the rest of the file is
        // not in the log, so claiming a whole-file digest here would be a lie.
        contentHash: sha256Hex(newText),
        bytes: byteLen(newText),
        detail:
          `replaced ${byteLen(oldText)} bytes with ${byteLen(newText)}` +
          `${replaceAll ? ' (all occurrences)' : ''}`,
        undecidable: false,
      })
    }
    case 'read':
    case 'read_image': {
      const raw = argString(args, 'file_path', 'path', 'filePath')
      if (!raw) return one({ kind: 'unknown', fidelity: 'opaque', detail: `${name} without a path`, undecidable: true })
      const offset = typeof args.offset === 'number' ? args.offset : undefined
      const limit = typeof args.limit === 'number' ? args.limit : undefined
      return one({
        kind: 'read',
        fidelity: 'observed',
        rawPath: raw,
        path: resolvePath(raw, cwd),
        detail:
          offset !== undefined || limit !== undefined
            ? `read a window (offset ${offset ?? 0}, limit ${limit ?? 'end'})`
            : 'read the file',
        undecidable: false,
      })
    }
    case 'grep':
    case 'glob': {
      const raw = argString(args, 'path') ?? cwd
      const pattern = argString(args, 'pattern') ?? ''
      return one({
        kind: 'search',
        fidelity: 'observed',
        rawPath: raw,
        path: raw ? resolvePath(raw, cwd) : undefined,
        source: pattern,
        detail: `searched for ${JSON.stringify(pattern)}${args.include ? ` in ${String(args.include)}` : ''}`,
        undecidable: false,
      })
    }
    case 'pwsh':
    case 'bash':
    case 'shell': {
      const command = argString(args, 'command') ?? ''
      return one({
        kind: 'shell',
        fidelity: 'undecidable',
        source: command,
        // A shell command's file effects are not reconstructible from the log.
        // Guessing them would turn audit evidence into speculation.
        detail: argString(args, 'description') ?? `ran ${command.slice(0, 80)}`,
        undecidable: true,
      })
    }
    case 'web_search':
    case 'web_fetch': {
      const query = argString(args, 'query', 'url') ?? ''
      return one({
        kind: 'network',
        fidelity: 'observed',
        source: query,
        detail: `queried ${JSON.stringify(query.slice(0, 80))}`,
        undecidable: false,
      })
    }
    case 'subagent':
    case 'subagent_fork':
    case 'send_message':
    case 'interrupt_agent':
    case 'workflow':
    case 'ralph': {
      return one({
        kind: 'delegation',
        fidelity: 'observed',
        source: argString(args, 'description', 'subagent_id', 'objective') ?? name,
        detail: `delegated work via ${name}`,
        undecidable: false,
      })
    }
    case 'todo_write':
    case 'job_output':
    case 'job_kill':
    case 'job_list':
    case 'ask_user_question':
    case 'exit_plan_mode':
    case 'create_goal':
    case 'update_goal':
    case 'get_goal': {
      return one({
        kind: 'control',
        fidelity: 'observed',
        source: argString(args, 'job_id', 'objective') ?? '',
        detail: `called ${name}`,
        undecidable: false,
      })
    }
    default:
      return one({
        kind: 'unknown',
        fidelity: 'opaque',
        source: JSON.stringify(args).slice(0, 512),
        detail: `unrecognised tool ${name}`,
        undecidable: true,
      })
  }
}

/** One step in the history of a path. */
export interface VersionStep {
  seq?: number
  time: number
  callId: string
  toolName: string
  kind: EffectKind
  fidelity: Fidelity
  contentHash?: string
  bytes?: number
  detail: string
}

export interface FileVersionChain {
  path: string
  /** Ordered oldest first. */
  steps: VersionStep[]
  /** True when the session created the file (first effect is a whole-file write). */
  created: boolean
  /** True when the agent edited a file it never wrote — it pre-existed. */
  preexisting: boolean
  /** SHA-256 of the last whole-file content the log contains, when one exists. */
  lastExactHash?: string
  /** True when a shell command ran between two recorded versions of this path. */
  contaminated: boolean
  /** How many shell effects fell inside the chain's record-sequence window. */
  shellsInWindow: number
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
export function buildVersionChains(effects: Effect[]): Map<string, FileVersionChain> {
  const chains = new Map<string, FileVersionChain>()
  const shellSeqs: number[] = []
  for (const e of effects) {
    if (e.kind === 'shell' && e.seq !== undefined) shellSeqs.push(e.seq)
  }
  shellSeqs.sort((a, b) => a - b)

  for (const e of effects) {
    if (!e.path || (e.kind !== 'write' && e.kind !== 'edit' && e.kind !== 'read')) continue
    let chain = chains.get(e.path)
    if (!chain) {
      chain = {
        path: e.path,
        steps: [],
        created: false,
        preexisting: false,
        contaminated: false,
        shellsInWindow: 0,
      }
      chains.set(e.path, chain)
    }
    chain.steps.push({
      seq: e.seq,
      time: e.time,
      callId: e.callId,
      toolName: e.toolName,
      kind: e.kind,
      fidelity: e.fidelity,
      contentHash: e.contentHash,
      bytes: e.bytes,
      detail: e.detail,
    })
    if (e.kind === 'write' && e.fidelity === 'exact') chain.lastExactHash = e.contentHash
  }

  /** Count shell effects whose record sequence falls inside [lo, hi]. */
  const shellsBetween = (lo: number, hi: number): number => {
    let count = 0
    for (const seq of shellSeqs) {
      if (seq < lo) continue
      if (seq > hi) break
      count++
    }
    return count
  }

  for (const chain of chains.values()) {
    chain.steps.sort((a, b) => (a.seq ?? a.time) - (b.seq ?? b.time))
    const first = chain.steps[0]
    chain.created = first?.kind === 'write' && first.fidelity === 'exact'
    chain.preexisting = first?.kind === 'read' || first?.kind === 'edit'

    const seqs = chain.steps.map((s) => s.seq).filter((s): s is number => s !== undefined)
    if (seqs.length > 0 && shellSeqs.length > 0) {
      const lo = Math.min(...seqs)
      const hi = Math.max(...seqs)
      chain.shellsInWindow = shellsBetween(lo, hi)
      chain.contaminated = chain.shellsInWindow > 0
    }
  }
  return chains
}

/** Aggregate counts per effect kind, for reporting. */
export function summarizeEffects(effects: Effect[]): Record<EffectKind, number> {
  const out = {
    read: 0,
    write: 0,
    edit: 0,
    search: 0,
    shell: 0,
    network: 0,
    delegation: 0,
    control: 0,
    unknown: 0,
  } satisfies Record<EffectKind, number>
  for (const e of effects) out[e.kind]++
  return out
}
