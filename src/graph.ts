// dsh-ledger — execution graph.
//
// DSH writes an append-only event log, not a document: a single assistant turn is
// spread over hundreds of records (streaming chunks, a complete message, a tool
// call, its result, step boundaries). This module reconstructs the shape a human
// or a policy engine can reason about — turns, steps, tool calls with their
// results, token accounting, and the anomalies worth looking at.
//
// Everything here is derived from record fields observed in real sessions, and
// nothing is inferred that the log does not state. Where a record type is unknown
// it is counted, not guessed at.
import type { RawRecord } from './reader.js'
import { effectsOf, type Effect } from './effects.js'

export interface SessionHeader {
  id?: string
  createdAt?: number
  cwd?: string
  delegationDepth?: number
  agentPreset?: string
}

export interface TokenUsage {
  inputTokens: number
  outputTokens: number
  cacheReadTokens: number
  reasoningTokens: number
  /** Number of usage-bearing assistant messages aggregated here. */
  messages: number
}

export const emptyUsage = (): TokenUsage => ({
  inputTokens: 0,
  outputTokens: 0,
  cacheReadTokens: 0,
  reasoningTokens: 0,
  messages: 0,
})

function addUsage(target: TokenUsage, u: Partial<TokenUsage> | undefined): void {
  if (!u) return
  target.inputTokens += u.inputTokens ?? 0
  target.outputTokens += u.outputTokens ?? 0
  target.cacheReadTokens += u.cacheReadTokens ?? 0
  target.reasoningTokens += u.reasoningTokens ?? 0
  target.messages += 1
}

export interface ToolCallEvent {
  callId: string
  name: string
  /** Parsed arguments; `{}` when the log's argument string was empty/unparsable. */
  arguments: Record<string, unknown>
  /** Raw argument string exactly as logged. */
  rawArguments: string
  turn: number
  step: number
  seq?: number
  time: number
  frameIndex: number
  frameStart: number
}

export interface ToolResultEvent {
  callId: string
  isError: boolean
  /** Flattened text of every text block in the result. */
  text: string
  textBytes: number
  time: number
  seq?: number
  frameIndex: number
}

export interface ToolCallRecord {
  call: ToolCallEvent
  result?: ToolResultEvent
  /** Wall-clock duration when both call and result are present. */
  durationMs?: number
  effects: Effect[]
}

export interface StepNode {
  turn: number
  step: number
  startedAt?: number
  endedAt?: number
  durationMs?: number
  /** True when no step/end record was seen for this step. */
  unterminated: boolean
  calls: string[]
}

export interface TurnNode {
  turn: number
  startedAt?: number
  endedAt?: number
  durationMs?: number
  /** `reason.kind` from turn/end, e.g. `completed`, `aborted`. */
  endReason?: string
  unterminated: boolean
  steps: StepNode[]
  usage: TokenUsage
  calls: string[]
  errors: number
}

export type AnomalyKind =
  | 'llm-retry'
  | 'tool-error'
  | 'compaction'
  | 'turn-aborted'
  | 'approval-asked'
  | 'approval-denied'
  | 'permission-change'
  | 'unpaired-tool-call'
  | 'orphan-tool-result'

export interface Anomaly {
  kind: AnomalyKind
  turn?: number
  step?: number
  time?: number
  seq?: number
  /** Record index in the input array, for provenance back to the file. */
  recordIndex: number
  frameIndex: number
  frameStart: number
  detail: string
  data?: Record<string, unknown>
}

export interface GraphStats {
  records: number
  parsed: number
  unparsable: number
  byType: Record<string, number>
  streamingRecords: number
  /** Assistant reasoning characters seen in streaming deltas (never retained). */
  reasoningChars: number
  toolCalls: number
  toolResults: number
  paired: number
}

export interface ExecutionGraph {
  session: SessionHeader
  /** Governance as the session started. */
  governance: { permissionPreset?: string; sandboxMode?: string; approvalPolicy?: string }
  /** Governance as of the last record — differs when a preset changed mid-session. */
  governanceFinal: { permissionPreset?: string; sandboxMode?: string; approvalPolicy?: string }
  turns: TurnNode[]
  calls: ToolCallRecord[]
  callIndex: Map<string, number>
  usage: TokenUsage
  usageByModel: Map<string, TokenUsage>
  anomalies: Anomaly[]
  /** Assistant text blocks, in order. */
  assistantTexts: { turn: number; step: number; text: string; id?: string }[]
  userMessages: { turn: number; text: string; time: number }[]
  stats: GraphStats
}

/** Record types that are streaming deltas rather than authoritative events. */
const STREAMING_TYPES = new Set([
  'assistant/chunk',
  'reasoning-chunks',
  'tool-call-chunks',
  'text-chunks',
])

const asNumber = (v: unknown): number | undefined => (typeof v === 'number' ? v : undefined)
const asString = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined)

/**
 * Build an execution graph from parsed log records.
 *
 * Records arrive in file order, which the log guarantees (append-only), so the
 * graph is built in a single pass with no sorting.
 */
export function buildGraph(records: RawRecord[]): ExecutionGraph {
  const graph: ExecutionGraph = {
    session: {},
    governance: {},
    governanceFinal: {},
    turns: [],
    calls: [],
    callIndex: new Map(),
    usage: emptyUsage(),
    usageByModel: new Map(),
    anomalies: [],
    assistantTexts: [],
    userMessages: [],
    stats: {
      records: records.length,
      parsed: 0,
      unparsable: 0,
      byType: {},
      streamingRecords: 0,
      reasoningChars: 0,
      toolCalls: 0,
      toolResults: 0,
      paired: 0,
    },
  }

  const turnNodes = new Map<number, TurnNode>()
  const stepNodes = new Map<string, StepNode>()
  const callsById = new Map<string, ToolCallRecord>()
  const resultsById = new Map<string, ToolResultEvent>()
  const seenMessageIds = new Set<string>()

  const turnOf = (turn: number): TurnNode => {
    let node = turnNodes.get(turn)
    if (!node) {
      node = {
        turn,
        unterminated: true,
        steps: [],
        usage: emptyUsage(),
        calls: [],
        errors: 0,
      }
      turnNodes.set(turn, node)
      graph.turns.push(node)
    }
    return node
  }

  records.forEach((record, recordIndex) => {
    const value = record.value as Record<string, unknown> | null
    if (!value || typeof value !== 'object') {
      graph.stats.unparsable++
      return
    }
    const type = asString(value.type)
    if (!type) {
      graph.stats.unparsable++
      return
    }
    graph.stats.parsed++
    graph.stats.byType[type] = (graph.stats.byType[type] ?? 0) + 1
    if (STREAMING_TYPES.has(type)) {
      graph.stats.streamingRecords++
      const data = value.data as Record<string, unknown> | undefined
      const texts = data?.texts
      if (Array.isArray(texts)) {
        for (const t of texts) if (typeof t === 'string') graph.stats.reasoningChars += t.length
      }
      const text = data?.text
      if (typeof text === 'string') graph.stats.reasoningChars += text.length
      return
    }

    const data = (value.data ?? {}) as Record<string, unknown>
    const seq = asNumber(value.seq) ?? asNumber(value.seq0)
    const time = asNumber(value.time) ?? asNumber(value.time0) ?? 0
    const anomaly = (kind: AnomalyKind, detail: string, extra?: Partial<Anomaly>): void => {
      graph.anomalies.push({
        kind,
        time,
        seq,
        detail,
        frameIndex: record.frameIndex,
        frameStart: record.frameStart,
        recordIndex,
        ...extra,
      })
    }

    switch (type) {
      case 'session': {
        graph.session = {
          id: asString(value.id),
          createdAt: asNumber(value.createdAt),
          cwd: asString(value.cwd),
          delegationDepth: asNumber(value.delegationDepth),
          agentPreset: asString(value.agentPreset),
        }
        break
      }
      case 'permission/preset': {
        const preset = asString(data.preset)
        if (preset) {
          graph.governance.permissionPreset ??= preset
          graph.governanceFinal.permissionPreset = preset
        }
        break
      }
      case 'sandbox/mode': {
        const mode = asString(data.mode)
        if (mode) {
          graph.governance.sandboxMode ??= mode
          graph.governanceFinal.sandboxMode = mode
        }
        break
      }
      case 'approval/policy': {
        const policy = asString(data.policy)
        if (policy) {
          graph.governance.approvalPolicy ??= policy
          graph.governanceFinal.approvalPolicy = policy
        }
        break
      }
      case 'turn/start': {
        const node = turnOf(asNumber(data.turn) ?? 0)
        node.startedAt = time
        break
      }
      case 'turn/end': {
        const turn = asNumber(data.turn) ?? 0
        const node = turnOf(turn)
        node.endedAt = time
        node.unterminated = false
        const reason = data.reason as Record<string, unknown> | undefined
        node.endReason = asString(reason?.kind)
        if (node.startedAt !== undefined) node.durationMs = node.endedAt - node.startedAt
        if (node.endReason && node.endReason !== 'completed') {
          anomaly('turn-aborted', `turn ${turn} ended with ${node.endReason}`, { turn })
        }
        break
      }
      case 'step/start': {
        const turn = asNumber(data.turn) ?? 0
        const step = asNumber(data.step) ?? 0
        const node: StepNode = { turn, step, startedAt: time, unterminated: true, calls: [] }
        stepNodes.set(`${turn}/${step}`, node)
        turnOf(turn).steps.push(node)
        break
      }
      case 'step/end': {
        const turn = asNumber(data.turn) ?? 0
        const step = asNumber(data.step) ?? 0
        const node = stepNodes.get(`${turn}/${step}`)
        if (node) {
          node.endedAt = time
          node.unterminated = false
          if (node.startedAt !== undefined) node.durationMs = node.endedAt - node.startedAt
        }
        break
      }
      case 'user/message': {
        const content = data.content
        const text = Array.isArray(content)
          ? content
              .map((block) => {
                const b = block as Record<string, unknown>
                return b.type === 'text' && typeof b.text === 'string' ? b.text : ''
              })
              .join('')
          : ''
        graph.userMessages.push({ turn: turnNodes.size, text, time })
        break
      }
      case 'assistant/message': {
        const message = (data.message ?? {}) as Record<string, unknown>
        const id = asString(message.id)
        // Retries can re-emit the same assistant message; count usage once.
        if (id && seenMessageIds.has(id)) break
        if (id) seenMessageIds.add(id)
        const turn = asNumber(data.turn) ?? 0
        const step = asNumber(data.step) ?? 0
        const source = (message.source ?? {}) as Record<string, unknown>
        const model = asString(source.model) ?? '(unknown)'
        const usage = data.usage as Record<string, number> | undefined
        const parsed: Partial<TokenUsage> | undefined = usage
          ? {
              inputTokens: usage.inputTokens ?? 0,
              outputTokens: usage.outputTokens ?? 0,
              cacheReadTokens: usage.cacheReadTokens ?? 0,
              reasoningTokens: usage.reasoningTokens ?? 0,
            }
          : undefined
        addUsage(graph.usage, parsed)
        addUsage(turnOf(turn).usage, parsed)
        let modelUsage = graph.usageByModel.get(model)
        if (!modelUsage) {
          modelUsage = emptyUsage()
          graph.usageByModel.set(model, modelUsage)
        }
        addUsage(modelUsage, parsed)

        const content = message.content
        if (Array.isArray(content)) {
          for (const block of content) {
            const b = block as Record<string, unknown>
            if (b.type === 'text' && typeof b.text === 'string') {
              graph.assistantTexts.push({ turn, step, text: b.text, id })
            }
          }
        }
        break
      }
      case 'tool/call': {
        const call = (data ?? {}) as Record<string, unknown>
        const callId = asString(call.callId) ?? ''
        const rawArguments = asString(call.arguments) ?? ''
        let args: Record<string, unknown> = {}
        if (rawArguments.trim().length > 0) {
          try {
            const parsedArgs = JSON.parse(rawArguments) as unknown
            if (parsedArgs && typeof parsedArgs === 'object') args = parsedArgs as Record<string, unknown>
            else anomaly('tool-error', `tool call ${call.name} arguments were not an object`)
          } catch {
            anomaly('tool-error', `tool call ${call.name} arguments were not valid JSON`)
          }
        }
        const event: ToolCallEvent = {
          callId,
          name: asString(call.name) ?? '(unknown)',
          arguments: args,
          rawArguments,
          turn: asNumber(call.turn) ?? 0,
          step: asNumber(call.step) ?? 0,
          seq,
          time,
          frameIndex: record.frameIndex,
          frameStart: record.frameStart,
        }
        const entry: ToolCallRecord = {
          call: event,
          effects: effectsOf(event, graph.session.cwd),
        }
        graph.callIndex.set(callId, graph.calls.length)
        graph.calls.push(entry)
        callsById.set(callId, entry)
        graph.stats.toolCalls++
        const turnNode = turnOf(event.turn)
        turnNode.calls.push(callId)
        const stepNode = stepNodes.get(`${event.turn}/${event.step}`)
        if (stepNode) stepNode.calls.push(callId)
        break
      }
      case 'tool/result': {
        const message = (data.message ?? {}) as Record<string, unknown>
        const source = (message.source ?? {}) as Record<string, unknown>
        const callId = asString(source.callId) ?? ''
        let isError = false
        let text = ''
        const content = message.content
        if (Array.isArray(content)) {
          for (const block of content) {
            const b = block as Record<string, unknown>
            if (b.isError === true) isError = true
            const inner = b.content
            if (Array.isArray(inner)) {
              for (const part of inner) {
                const p = part as Record<string, unknown>
                if (p.type === 'text' && typeof p.text === 'string') text += p.text
              }
            }
          }
        }
        const result: ToolResultEvent = {
          callId,
          isError,
          text,
          textBytes: Buffer.byteLength(text, 'utf8'),
          time,
          seq,
          frameIndex: record.frameIndex,
        }
        resultsById.set(callId, result)
        graph.stats.toolResults++
        const entry = callsById.get(callId)
        if (entry) {
          entry.result = result
          if (entry.call.time && time) entry.durationMs = time - entry.call.time
          if (isError) {
            turnOf(entry.call.turn).errors++
            anomaly('tool-error', `${entry.call.name} failed: ${text.slice(0, 160)}`, {
              turn: entry.call.turn,
              step: entry.call.step,
              data: { callId, tool: entry.call.name },
            })
          }
        } else {
          anomaly('orphan-tool-result', `result for unknown call ${callId}`)
        }
        break
      }
      case 'approval/asked': {
        anomaly('approval-asked', `approval requested for ${String(data.toolName)}`, {
          turn: asNumber(data.turn),
          data: { id: data.id, callId: data.callId, reason: data.reason },
        })
        break
      }
      case 'approval/decided': {
        const outcome = asString(data.outcome) ?? 'unknown'
        if (outcome.startsWith('denied') || outcome === 'rejected') {
          anomaly('approval-denied', `approval ${outcome}`, { data: { id: data.id } })
        }
        break
      }
      case 'command/run': {
        if (asString(data.name) === 'permission') {
          anomaly('permission-change', `permission preset changed to ${String(data.args ?? '').trim()}`, {
            data: { commandId: data.commandId, args: data.args },
          })
        }
        break
      }
      case 'compaction/start': {
        anomaly('compaction', `context compaction started in turn ${String(data.turn ?? '?')}`, {
          turn: asNumber(data.turn),
          data: { compactionId: data.compactionId },
        })
        break
      }
      case 'llm/retry': {
        const failure = (data.failure ?? {}) as Record<string, unknown>
        anomaly(
          'llm-retry',
          `retry ${String(data.retry)}/${String(data.maxRetries)} after ${String(failure.code ?? 'error')}`,
          {
            turn: asNumber(data.turn),
            step: asNumber(data.step),
            data: {
              retryId: data.retryId,
              code: failure.code,
              message: failure.message,
              delayMs: data.delayMs,
            },
          },
        )
        break
      }
      default:
        // Unknown record types are already counted in stats.byType.
        break
    }
  })

  // Unpaired calls are a real integrity signal: the log says a tool ran and never
  // recorded what happened.
  for (const entry of graph.calls) {
    if (entry.result) graph.stats.paired++
    else {
      graph.anomalies.push({
        kind: 'unpaired-tool-call',
        turn: entry.call.turn,
        step: entry.call.step,
        time: entry.call.time,
        seq: entry.call.seq,
        detail: `no result recorded for ${entry.call.name}`,
        frameIndex: entry.call.frameIndex,
        frameStart: entry.call.frameStart,
        recordIndex: -1,
        data: { callId: entry.call.callId },
      })
    }
  }

  graph.turns.sort((a, b) => a.turn - b.turn)
  for (const turn of graph.turns) turn.steps.sort((a, b) => a.step - b.step)
  graph.calls.sort((a, b) => (a.call.seq ?? a.call.time) - (b.call.seq ?? b.call.time))
  graph.callIndex.clear()
  graph.calls.forEach((entry, i) => graph.callIndex.set(entry.call.callId, i))
  graph.anomalies.sort((a, b) => (a.seq ?? a.time ?? 0) - (b.seq ?? b.time ?? 0))
  return graph
}
