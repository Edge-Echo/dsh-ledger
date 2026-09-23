// dsh-ledger — compliance export.
//
// DSH4's guidance was explicit: *do not invent another audit format, integrate with
// the one that exists*. So this module emits `dsh-audit-trail/compliance/1`, the
// versioned JSONL that `dsh-audit-trail` already defines and can verify.
//
// Two deliberate choices:
//
//  1. The chain spec (canonical record, hash rule, schema id) is reimplemented here
//     in ~40 lines so the ledger keeps its zero-dependency promise — and a
//     conformance test asserts this implementation is **byte-identical** to theirs
//     and that their own `verifyComplianceJsonl` accepts our output. When the real
//     package is installed, `emitCompliance` prefers its functions outright.
//
//  2. Only events whose meaning maps cleanly onto their `kind` values are emitted.
//     Approvals, retries and compactions have no equivalent kind, so they become
//     `flags` on the records they belong to plus a sidecar file — never a record
//     stuffed into a kind that means something else.
//
// Severity is where this library adds something: their ladder (info/low/medium/
// high/critical) is fed by the effect attribution, including the honest
// `undecidable` marking for shell commands.
import { createHash } from 'node:crypto'
import type { Effect, EffectKind } from './effects.js'
import type { ExecutionGraph, ToolCallRecord } from './graph.js'

/** The schema id of the format this module emits. */
export const COMPLIANCE_SCHEMA = 'dsh-audit-trail/compliance/1'
/** The canonicalisation prefix used inside the hash chain. */
export const CANONICAL_PREFIX = 'dsh-audit-trail/canonical/1'

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

/** Ordered least to most severe, matching the upstream ladder. */
export const SEVERITIES: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'] as const

export const severityRank = (s: Severity): number => SEVERITIES.indexOf(s)

/** The `kind` values the upstream schema defines. */
export const AUDIT_KINDS = [
  'session_live',
  'turn_start',
  'turn_end',
  'step_start',
  'step_end',
  'user_message',
  'assistant_message',
  'assistant_chunk',
  'todo_update',
  'request_header',
  'request_context',
  'tool_call',
  'tool_result',
  'tool_dispatch',
  'tool_registered',
] as const
export type AuditKind = (typeof AUDIT_KINDS)[number]

/** One payload row of the compliance format, in upstream field order. */
export interface CompliancePayload {
  sessionId: string
  ts: number
  kind: AuditKind
  turn: number | null
  step: number | null
  toolName: string | null
  callId: string | null
  argsDigest: string | null
  status: string | null
  durationMs: number | null
  severity: Severity
  flags: string[]
  summary: string
  detail: string | null
  filesRead: string[]
  filesWritten: string[]
  network: string[]
  actor: string | null
  sourceType: string
  sourceSeq: number | null
}

export interface ComplianceLine {
  recordId: number
  prevHash: string | null
  payload: CompliancePayload
  hashSelf: string
}

const sha256Hex = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex')

/**
 * Deterministic JSON: object keys sorted lexicographically, arrays keep order.
 * Matches upstream `stableStringify`, which the hash chain depends on.
 */
export function stableStringify(value: unknown): string {
  const sortValue = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(sortValue)
    if (v !== null && typeof v === 'object') {
      const out: Record<string, unknown> = {}
      for (const key of Object.keys(v as Record<string, unknown>).sort()) {
        out[key] = sortValue((v as Record<string, unknown>)[key])
      }
      return out
    }
    return v
  }
  return JSON.stringify(sortValue(value))
}

/**
 * The exact field vector the upstream hash covers. It is an *array*, and its order
 * is part of the format — a reordering silently changes every downstream hash, so
 * this is copied field for field rather than derived.
 */
export function canonicalRecordFields(p: CompliancePayload): unknown[] {
  return [
    p.sessionId,
    p.ts,
    p.kind,
    p.turn ?? null,
    p.step ?? null,
    p.toolName ?? null,
    p.callId ?? null,
    p.argsDigest ?? null,
    p.status ?? null,
    p.durationMs ?? null,
    p.severity,
    [...new Set(p.flags)].sort(),
    p.summary,
    p.detail ?? null,
    p.filesRead,
    p.filesWritten,
    p.network,
    p.actor ?? null,
    p.sourceType,
    p.sourceSeq ?? null,
  ]
}

/** The canonical text of one record, as hashed. */
export function canonicalRecord(p: CompliancePayload): string {
  return `${CANONICAL_PREFIX}\n${stableStringify(canonicalRecordFields(p))}\n`
}

/** Hash of one record given the previous record's hash. */
export function chainHash(prevHash: string | null, p: CompliancePayload): string {
  return sha256Hex(`${prevHash ?? ''}\n${canonicalRecord(p)}\n`)
}

// ── risk assessment ────────────────────────────────────────────────────────

/** Paths whose appearance in a read or write is worth a `critical` flag. */
const SENSITIVE_PATTERNS: [RegExp, string][] = [
  [/(^|[\\/])\.env(\..*)?$/i, 'dotenv'],
  [/(^|[\\/])id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/i, 'ssh-key'],
  [/(^|[\\/])\.(ssh|aws|gnupg|docker)[\\/]/i, 'credential-dir'],
  [/(^|[\\/])\.npmrc$/i, 'npmrc'],
  [/(^|[\\/])\.git-credentials$/i, 'git-credentials'],
  [/(^|[\\/])\.git[\\/]config$/i, 'git-config'],
  [/\.(pem|pfx|p12|key|keystore|jks)$/i, 'key-material'],
  [/(secret|credential|passwd|password|apikey|api_key|access_token)/i, 'secret-named'],
  [/(^|[\\/])\.dsh[\\/]profiles[\\/]/i, 'dsh-profile'],
]

/** Commands whose effect is destructive rather than merely opaque. */
const DESTRUCTIVE_PATTERNS: [RegExp, string][] = [
  [/\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\b/i, 'rm-recursive-force'],
  [/\bRemove-Item\b[^\n]*-Recurse\b[^\n]*-Force\b/i, 'remove-item-recursive'],
  [/\b(Format-Volume|format\s+[a-z]:)/i, 'format-volume'],
  [/\bgit\s+reset\s+--hard\b/i, 'git-reset-hard'],
  [/\bgit\s+clean\s+-[a-z]*f/i, 'git-clean-force'],
  [/\b(DROP\s+(TABLE|DATABASE)|TRUNCATE\s+TABLE)\b/i, 'sql-destructive'],
  [/\b(npm|pnpm|yarn)\s+publish\b/i, 'package-publish'],
  [/\bgit\s+push\b[^\n]*--force\b/i, 'git-push-force'],
  [/\b(shutdown|Stop-Computer|Restart-Computer)\b/i, 'host-power'],
  [/[>]{1,2}\s*[A-Za-z]:[\\/](Windows|Program Files)/i, 'system-path-write'],
  [/\bcurl\b[^\n]*\|\s*(ba|z|fi)?sh\b/i, 'pipe-to-shell'],
  [/\b(Invoke-Expression|iex)\b/i, 'invoke-expression'],
]

/** Recursive deletes are scored by target, so they need their own handling. */
const RECURSIVE_DELETE = new Set(['rm-recursive-force', 'remove-item-recursive'])

const WIN_ROOTISH = /^[a-z]:\\(\*?)?$/i
const WIN_SYSTEMISH = /^[a-z]:\\(windows|program files(\s*\(x86\))?|programdata|recovery|perflogs)\b/i
const NIX_ROOTISH = /^\/\*?$/
const NIX_SYSTEMISH = /^\/(etc|usr|var|bin|sbin|boot|lib|opt|dev|proc|sys)\b/

/** Pull the paths a command names, best effort — used only to pick a severity. */
export function commandTargets(command: string): string[] {
  const found = new Set<string>()
  for (const match of command.matchAll(/"[^"]*"|'[^']*'|[^\s"'|;)]+/g)) {
    const token = match[0].replace(/^["']|["']$/g, '')
    if (/^[a-z]:\\/i.test(token) || token.startsWith('/')) found.add(token.replace(/[\\/]+$/, ''))
  }
  return [...found]
}

/** `$tmp = "C:\..."` assignments, so a delete of `$tmp` can be attributed. */
function variablePaths(command: string): Map<string, string> {
  const raw = new Map<string, string>()
  for (const m of command.matchAll(/\$([A-Za-z_]\w*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s;|)]+))/g)) {
    raw.set(m[1]!, (m[2] ?? m[3] ?? m[4] ?? '').trim())
  }
  // One pass of interpolation, so `$out = "$base\sub"` resolves when `$base` is a
  // literal. Deeper chains are left unresolved rather than guessed at.
  const resolved = new Map<string, string>()
  for (const [name, value] of raw) {
    const expanded = value.replace(/\$([A-Za-z_]\w*)/g, (whole, ref: string) => raw.get(ref) ?? whole)
    if (/^[a-z]:\\/i.test(expanded) || expanded.startsWith('/')) {
      resolved.set(name, expanded.replace(/[\\/]+$/, ''))
    }
  }
  return resolved
}

/** The statement a match sits in, bounded by shell separators, braces and newlines. */
function statementAround(command: string, index: number): string {
  const boundary = (c: string): boolean => c === ';' || c === '\n' || c === '|' || c === '}' || c === '{'
  let start = index
  while (start > 0 && !boundary(command[start - 1]!)) start--
  let end = index
  while (end < command.length && !boundary(command[end]!)) end++
  return command.slice(start, end)
}

const normPath = (p: string): string => p.replace(/\//g, '\\').replace(/\\+$/, '').toLowerCase()

/**
 * Where a recursive delete points.
 *
 * Scoring the verb alone called 126 temp-directory cleanups "critical" on a real
 * session. Scoring every path in the command then flagged Edge's own install path
 * as a delete target, because the command both launched Edge and cleaned a temp
 * directory. Both are alarm inflation, which is how a tool gets ignored — so the
 * target is read from the statement the delete verb is in, with `$var` assignments
 * resolved first. Workspace-internal cleanup is high; a system path, the workspace
 * root, or an unreadable target stays critical.
 */
function classifyRecursiveDelete(
  command: string,
  cwd: string | undefined,
  matchIndex: number,
): { severity: Severity; flag: string } {
  const variables = variablePaths(command)
  let statement = statementAround(command, matchIndex)
  for (const [name, value] of variables) {
    statement = statement.split(`$${name}`).join(`"${value}"`)
  }

  const targets = commandTargets(statement)
  if (targets.length === 0) {
    // No absolute path, but a bare word operand is still a real target and, with a
    // known cwd, it is workspace-relative by definition.
    const operands = [...statement.matchAll(/(?:^|\s)([^\s"'|;)\-${}][^\s"'|;)]*)/g)]
      .map((m) => m[1]!.trim())
      .filter((t) => t.length > 0 && !/^(Remove-Item|rm|del|erase|rd|rmdir|-Recurse|-Force|\/s|\/q)$/i.test(t))
    if (operands.length > 0 && cwd) {
      return { severity: 'high', flag: 'destructive:in-workspace' }
    }
    // A recursive delete whose target the command text does not reveal. Calling this
    // critical would claim knowledge of a path we never saw — the same mistake as
    // guessing a shell command's file effects. It is loud, and labelled for what it is.
    return { severity: 'high', flag: 'destructive:target-unresolved' }
  }

  const cwdNorm = cwd ? normPath(cwd) : undefined
  let sawInside = false
  for (const target of targets) {
    if (
      WIN_ROOTISH.test(target) ||
      WIN_SYSTEMISH.test(target) ||
      NIX_ROOTISH.test(target) ||
      NIX_SYSTEMISH.test(target)
    ) {
      return { severity: 'critical', flag: 'destructive:system-target' }
    }
    const norm = normPath(target)
    if (cwdNorm && (norm === cwdNorm || norm === `${cwdNorm}\\*`)) {
      return { severity: 'critical', flag: 'destructive:workspace-root' }
    }
    if (cwdNorm && norm.startsWith(`${cwdNorm}\\`)) sawInside = true
  }
  return sawInside
    ? { severity: 'high', flag: 'destructive:in-workspace' }
    : { severity: 'critical', flag: 'destructive:outside-workspace' }
}

export interface RiskAssessment {
  severity: Severity
  flags: string[]
}

/** Workspace-relative check that keeps the comparison case-insensitive on Windows. */
function isOutsideWorkspace(path: string, cwd?: string): boolean {
  if (!cwd) return false
  const norm = (s: string) => s.replace(/\//g, '\\').toLowerCase()
  const p = norm(path)
  const root = norm(cwd).replace(/\\+$/, '')
  return !p.startsWith(root + '\\') && p !== root
}

/**
 * Score one effect. This is the part of the compliance export that the ledger
 * contributes beyond what a plain recorder can see: it knows the fidelity of each
 * effect, so it can be loud where the log is decisive and explicit where it is not.
 */
export function assessEffect(effect: Effect, cwd?: string): RiskAssessment {
  const flags: string[] = []
  let severity: Severity = 'info'

  const raise = (s: Severity): void => {
    if (severityRank(s) > severityRank(severity)) severity = s
  }

  const sensitiveHit = effect.path ? SENSITIVE_PATTERNS.find(([re]) => re.test(effect.path!)) : undefined
  if (sensitiveHit) flags.push(`sensitive-path:${sensitiveHit[1]}`)

  switch (effect.kind) {
    case 'read': {
      // Reading a credential file is an access event even though nothing changed.
      if (sensitiveHit) raise('critical')
      break
    }
    case 'write':
    case 'edit': {
      if (sensitiveHit) raise('critical')
      if (effect.path && isOutsideWorkspace(effect.path, cwd)) {
        flags.push('outside-workspace')
        raise('high')
      } else {
        raise('low')
      }
      break
    }
    case 'shell': {
      flags.push('shell')
      // The log cannot say what a shell command touched, and saying so is the point.
      if (effect.undecidable) flags.push('effects-undecidable')
      raise('medium')
      for (const [re, name] of DESTRUCTIVE_PATTERNS) {
        const match = effect.source ? re.exec(effect.source) : null
        if (!match) continue
        if (RECURSIVE_DELETE.has(name)) {
          const verdict = classifyRecursiveDelete(effect.source!, cwd, match.index)
          flags.push(verdict.flag)
          raise(verdict.severity)
        } else {
          flags.push(`destructive:${name}`)
          raise(name === 'package-publish' || name === 'host-power' ? 'high' : 'critical')
        }
      }
      break
    }
    case 'network':
      raise('low')
      break
    case 'delegation':
    case 'control':
    case 'search':
      raise('info')
      break
    case 'unknown':
      flags.push('unclassified-tool')
      raise('medium')
      break
  }

  if (effect.fidelity === 'partial' && (effect.kind === 'write' || effect.kind === 'edit')) {
    flags.push('partial-fidelity')
  }
  return { severity, flags }
}

// ── ledger facts -> compliance records ─────────────────────────────────────

/**
 * Fold one tool call's effects into the fields the schema exposes: the maximum
 * severity wins, every flag is kept, and file/network attribution is unioned.
 */
function callStatements(
  call: ToolCallRecord,
  cwd?: string,
): { severity: Severity; flags: string[]; filesRead: string[]; filesWritten: string[]; network: string[] } {
  let severity: Severity = 'info'
  const flags = new Set<string>()
  const filesRead = new Set<string>()
  const filesWritten = new Set<string>()
  const network = new Set<string>()

  for (const effect of call.effects) {
    const { severity: s, flags: f } = assessEffect(effect, cwd)
    if (severityRank(s) > severityRank(severity)) severity = s
    for (const flag of f) flags.add(flag)
    if (effect.kind === 'read' && effect.path) filesRead.add(effect.path)
    if ((effect.kind === 'write' || effect.kind === 'edit') && effect.path) filesWritten.add(effect.path)
    if (effect.kind === 'network' && effect.source) network.add(effect.source)
  }
  if (call.result?.isError) {
    flags.add('tool-error')
    if (severityRank(severity) < severityRank('medium')) severity = 'medium'
  }
  if (!call.result) {
    flags.add('unpaired-call')
    if (severityRank(severity) < severityRank('high')) severity = 'high'
  }
  return {
    severity,
    flags: [...flags].sort(),
    filesRead: [...filesRead].sort(),
    filesWritten: [...filesWritten].sort(),
    network: [...network].sort(),
  }
}

const effectSummaryLine = (effects: Effect[]): string =>
  effects
    .map((e) => {
      if (e.kind === 'shell') return `shell: ${(e.source ?? '').slice(0, 120)}`
      if (e.path) return `${e.kind} ${e.path}`
      if (e.source) return `${e.kind} ${e.source.slice(0, 80)}`
      return `${e.kind} ${e.toolName}`
    })
    .join('; ')

/**
 * Convert a graph into compliance payloads.
 *
 * Records are emitted in log order so the resulting chain is also a timeline. The
 * ledger's own richer facts (effect fidelity, version chains, anomalies) go to the
 * sidecar rather than being forced into a kind that does not describe them.
 */
export function toCompliancePayloads(graph: ExecutionGraph): CompliancePayload[] {
  const sessionId = graph.session.id ?? 'unknown-session'
  const cwd = graph.session.cwd

  type Stamped = { ts: number; rank: number; payload: CompliancePayload }
  const stamped: Stamped[] = []

  // Records are ordered by their real event time, with a rank as the tiebreak so a
  // turn's start precedes its calls and its end follows them even when timestamps
  // collide at millisecond resolution.
  const push = (
    ts: number,
    rank: number,
    payload: Omit<CompliancePayload, 'sessionId' | 'sourceType' | 'ts'>,
  ): void => {
    stamped.push({
      ts,
      rank,
      payload: { sessionId, ts, sourceType: 'dsh-ledger', ...payload } as CompliancePayload,
    })
  }

  for (const turn of graph.turns) {
    const ts = turn.startedAt ?? graph.session.createdAt ?? 0
    push(ts, 0, {
      kind: 'turn_start',
      turn: turn.turn,
      step: null,
      toolName: null,
      callId: null,
      argsDigest: null,
      status: null,
      durationMs: null,
      severity: 'info',
      flags: [],
      summary: `turn ${turn.turn} started`,
      detail: null,
      filesRead: [],
      filesWritten: [],
      network: [],
      actor: graph.session.agentPreset ?? null,
      sourceSeq: null,
    })
  }

  // Tool calls carry the substance: they are the records with severity and files.
  for (const call of graph.calls) {
    const statements = callStatements(call, cwd)
    push(call.call.time, 1, {
      kind: 'tool_call',
      turn: call.call.turn,
      step: call.call.step,
      toolName: call.call.name,
      callId: call.call.callId,
      argsDigest: sha256Hex(call.call.rawArguments),
      status: call.result ? (call.result.isError ? 'error' : 'ok') : 'pending',
      durationMs: call.durationMs ?? null,
      severity: statements.severity,
      flags: statements.flags,
      summary: `${call.call.name}: ${effectSummaryLine(call.effects) || 'no effect recorded'}`,
      detail: statements.flags.includes('effects-undecidable')
        ? 'effect surface is not reconstructible from the log; the command verbatim plus the effect fidelity live in the sidecar'
        : null,
      filesRead: statements.filesRead,
      filesWritten: statements.filesWritten,
      network: statements.network,
      actor: graph.session.agentPreset ?? null,
      sourceSeq: call.call.seq ?? null,
    })
  }

  for (const turn of graph.turns) {
    const ts = turn.endedAt ?? turn.startedAt ?? 0
    push(ts, 2, {
      kind: 'turn_end',
      turn: turn.turn,
      step: null,
      toolName: null,
      callId: null,
      argsDigest: null,
      status: turn.endReason ?? (turn.unterminated ? 'unterminated' : 'completed'),
      durationMs: turn.durationMs ?? null,
      severity: turn.errors > 0 ? 'medium' : 'info',
      flags: turn.endReason && turn.endReason !== 'completed' ? [`turn:${turn.endReason}`] : [],
      summary: `turn ${turn.turn} ended (${turn.endReason ?? 'unterminated'})`,
      detail: turn.errors > 0 ? `${turn.errors} tool error(s) in this turn` : null,
      filesRead: [],
      filesWritten: [],
      network: [],
      actor: null,
      sourceSeq: null,
    })
  }

  // Governance events are the one anomaly that deserves to be loud on its own.
  for (const anomaly of graph.anomalies) {
    if (
      anomaly.kind !== 'permission-change' &&
      anomaly.kind !== 'approval-asked' &&
      anomaly.kind !== 'approval-denied'
    ) {
      continue
    }
    push(anomaly.time ?? 0, 3, {
      kind: 'session_live',
      turn: anomaly.turn ?? null,
      step: anomaly.step ?? null,
      toolName: null,
      callId: null,
      argsDigest: null,
      status: anomaly.kind,
      durationMs: null,
      severity: anomaly.kind === 'approval-denied' ? 'medium' : 'high',
      flags: [anomaly.kind],
      summary: anomaly.detail,
      detail: anomaly.data ? stableStringify(anomaly.data) : null,
      filesRead: [],
      filesWritten: [],
      network: [],
      actor: 'governance',
      sourceSeq: anomaly.seq ?? null,
    })
  }

  stamped.sort((a, b) => (a.ts === b.ts ? a.rank - b.rank : a.ts - b.ts))
  return stamped.map((s) => s.payload)
}

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
export function documentHash(
  prevHash: string,
  line: { recordId: number; prevHash: string | null; payload: CompliancePayload },
): string {
  return sha256Hex(`${prevHash}\n${stableStringify(line)}\n`)
}

/**
 * Build the chained JSONL document (header line + one record per line).
 *
 * `hashSelf` must not be part of the hashed object, so the signature is hashed
 * before the emitted line is assembled.
 */
export function complianceJsonl(payloads: CompliancePayload[], opts: { hashChain?: boolean } = {}): string {
  const hashChain = opts.hashChain !== false
  const lines: string[] = []
  lines.push(
    JSON.stringify({ schema: COMPLIANCE_SCHEMA, generatedAt: Date.now(), count: payloads.length, hashChain }),
  )
  let prevHash = ''
  payloads.forEach((payload, index) => {
    const signature = { recordId: index + 1, prevHash: prevHash || null, payload }
    const hashSelf = documentHash(prevHash, signature)
    lines.push(JSON.stringify(hashChain ? { ...signature, hashSelf } : signature))
    prevHash = hashChain ? hashSelf : ''
  })
  return `${lines.join('\n')}\n`
}

export interface ChainVerification {
  valid: boolean
  lines: number
  records: number
  issues: string[]
  /** Highest severity seen, useful for a quick risk read of a pack. */
  maxSeverity?: Severity
}

/** Independent verification of a chained JSONL document, without upstream installed. */
export function verifyComplianceChain(text: string): ChainVerification {
  const raw = text.split(/\r?\n/).filter((line) => line.trim() !== '')
  if (raw.length === 0) return { valid: false, lines: 0, records: 0, issues: ['empty document'] }

  const issues: string[] = []
  let header: { schema?: string; count?: number; hashChain?: boolean }
  try {
    header = JSON.parse(raw[0]!) as typeof header
  } catch (err) {
    return { valid: false, lines: raw.length, records: 0, issues: [`header is not JSON: ${(err as Error).message}`] }
  }
  if (header.schema !== COMPLIANCE_SCHEMA) issues.push(`unexpected schema: ${String(header.schema)}`)
  const hashChain = header.hashChain === true

  let prevHash = ''
  let maxSeverity: Severity = 'info'
  let records = 0
  for (let i = 1; i < raw.length; i++) {
    let line: { recordId?: number; prevHash?: string | null; payload?: CompliancePayload; hashSelf?: string }
    try {
      line = JSON.parse(raw[i]!) as typeof line
    } catch (err) {
      issues.push(`line ${i + 1}: not JSON (${(err as Error).message})`)
      continue
    }
    records++
    if (line.recordId === undefined || line.payload === undefined) {
      issues.push(`record ${String(line.recordId)} missing recordId/payload`)
      continue
    }
    if (hashChain) {
      if (line.hashSelf === undefined) {
        issues.push(`record ${String(line.recordId)} missing hashSelf`)
      } else {
        const signature = { recordId: line.recordId, prevHash: line.prevHash ?? null, payload: line.payload }
        if (documentHash(prevHash, signature) !== line.hashSelf) {
          issues.push(`record ${String(line.recordId)} hash mismatch`)
        }
      }
    }
    prevHash = hashChain ? String(line.hashSelf ?? '') : ''
    if (line.payload.severity && severityRank(line.payload.severity) > severityRank(maxSeverity)) {
      maxSeverity = line.payload.severity
    }
  }
  if (typeof header.count === 'number' && header.count !== records) {
    issues.push(`header count ${header.count} does not match ${records} record(s)`)
  }
  return { valid: issues.length === 0, lines: raw.length, records, issues, maxSeverity }
}

/**
 * Verify using the upstream package when it is installed, so a third party gets the
 * verdict from the reference implementation rather than from this one.
 */
export async function verifyComplianceWithUpstream(
  text: string,
): Promise<ChainVerification & { verifier: 'dsh-audit-trail' | 'dsh-ledger' }> {
  try {
    const mod = (await import('dsh-audit-trail' as string)) as {
      verifyComplianceJsonl?: (t: string) => { valid: boolean; lines: number; records: number; issues: string[] }
    }
    if (typeof mod.verifyComplianceJsonl === 'function') {
      const result = mod.verifyComplianceJsonl(text)
      const local = verifyComplianceChain(text)
      return { ...result, maxSeverity: local.maxSeverity, verifier: 'dsh-audit-trail' }
    }
  } catch {
    /* upstream not installed — fall back to the local implementation */
  }
  return { ...verifyComplianceChain(text), verifier: 'dsh-ledger' }
}

/** Counts by severity, for reporting. */
export function severityHistogram(payloads: CompliancePayload[]): Record<Severity, number> {
  const out: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 }
  for (const p of payloads) out[p.severity]++
  return out
}

/** Effect-kind totals, reused by the CLI's classify command. */
export function effectKindTotals(effects: Effect[]): Partial<Record<EffectKind, number>> {
  const out: Partial<Record<EffectKind, number>> = {}
  for (const e of effects) out[e.kind] = (out[e.kind] ?? 0) + 1
  return out
}
