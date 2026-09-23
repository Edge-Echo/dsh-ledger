#!/usr/bin/env node
// dsh-ledger CLI.
//
//   dsh-ledger report   <log> [--json]                     what the agent did
//   dsh-ledger classify <log> [--json] [--min-severity s]  effects by type and risk
//   dsh-ledger pack     <log> -o <out.zip|dir> [--key k.pem]  a transferable evidence pack
//   dsh-ledger verify   <pack|compliance.jsonl> [--manifest m.json] [--log l]
//   dsh-ledger keygen   [--out key.pem]                    an Ed25519 key for signing
//
// The pack is the deliverable for the audience DSH4 described: it contains a
// compliance JSONL in `dsh-audit-trail/compliance/1`, the Merkle manifest (optionally
// signed), a human report, and a sidecar with the facts the compliance schema cannot
// express — effect fidelity, undecidable shell effects, file version chains.
import { createPrivateKey, generateKeyPairSync } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync, statSync } from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'
import { deflateRawSync, crc32 } from 'node:zlib'

import {
  attest,
  buildVersionChains,
  findSessionLogs,
  readLedger,
  renderSummary,
  signManifest,
  verifyManifest,
  verifyManifestSignature,
  type Effect,
  type LedgerManifest,
  type LedgerSnapshot,
} from './index.js'
import {
  complianceJsonl,
  effectKindTotals,
  SEVERITIES,
  severityHistogram,
  severityRank,
  toCompliancePayloads,
  verifyComplianceWithUpstream,
  type Severity,
} from './compliance.js'

const USAGE = `dsh-ledger — verifiable execution ledger for DeepSeek Harness sessions

usage:
  dsh-ledger list                                   list session logs under $DSH_HOME
  dsh-ledger report   <log> [--json]                turns, tools, tokens, anomalies
  dsh-ledger classify <log> [--json] [--min-severity info|low|medium|high|critical]
  dsh-ledger pack     <log> -o <out.zip|dir> [--key <key.pem>] [--title <name>]
  dsh-ledger verify   <pack.zip|dir|compliance.jsonl> [--manifest <m.json>] [--log <log>]
  dsh-ledger keygen   [--out <key.pem>]

The evidence pack contains:
  compliance.jsonl   dsh-audit-trail/compliance/1, hash-chained (verifiable upstream)
  manifest.json      Merkle roots over the log's frames and records (+ signature)
  sidecar.jsonl      effect fidelity, undecidable shell effects, file version chains
  REPORT.md          human-readable summary
  VERIFY.md          how a third party checks the pack without this tool
`

interface Args {
  command: string
  positional: string[]
  flags: Map<string, string | true>
}

function parseArgs(argv: string[]): Args {
  const [command = '', ...rest] = argv
  const positional: string[] = []
  const flags = new Map<string, string | true>()
  const isFlag = (token: string): boolean => token.length > 1 && token.startsWith('-')
  for (let i = 0; i < rest.length; i++) {
    const token = rest[i]!
    // Both `-o value` and `--out value` are accepted; only the dashes are stripped.
    if (isFlag(token)) {
      const key = token.replace(/^-+/, '')
      const next = rest[i + 1]
      if (next !== undefined && !isFlag(next)) {
        flags.set(key, next)
        i++
      } else {
        flags.set(key, true)
      }
    } else {
      positional.push(token)
    }
  }
  return { command, positional, flags }
}

const flag = (args: Args, name: string): string | undefined => {
  const v = args.flags.get(name)
  return typeof v === 'string' ? v : undefined
}

function die(message: string): never {
  process.stderr.write(`error: ${message}\n`)
  process.exit(1)
}

function loadSnapshot(path: string): Promise<LedgerSnapshot> {
  return readLedger(path)
}

/** Resolve a log argument: a path, or a session id/prefix to search for. */
async function resolveLog(input: string): Promise<string> {
  try {
    if (statSync(input).isFile()) return resolve(input)
  } catch {
    /* not a path — try session ids */
  }
  const logs = await findSessionLogs()
  const matches = logs.filter((l) => l.sessionId.startsWith(input) || l.sessionId.includes(input))
  if (matches.length === 0) die(`no session log matches "${input}"`)
  if (matches.length > 1) {
    die(`"${input}" matches ${matches.length} sessions: ${matches.slice(0, 5).map((m) => m.sessionId).join(', ')}`)
  }
  return matches[0]!.path
}

// ── a minimal ZIP writer ───────────────────────────────────────────────────
// An evidence pack is only useful if it can be handed over as one file, and a
// dependency for that would defeat the point of a zero-dependency library.

interface ZipEntry {
  name: string
  data: Buffer
}

function writeZip(entries: ZipEntry[]): Buffer {
  const locals: Buffer[] = []
  const centrals: Buffer[] = []
  let offset = 0

  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8')
    const deflated = deflateRawSync(entry.data, { level: 9 })
    const useDeflate = deflated.length < entry.data.length
    const body = useDeflate ? deflated : entry.data
    const method = useDeflate ? 8 : 0
    const crc = crc32(entry.data) >>> 0

    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4) // version needed
    local.writeUInt16LE(0x0800, 6) // UTF-8 names
    local.writeUInt16LE(method, 8)
    local.writeUInt16LE(0, 10) // time
    local.writeUInt16LE(0x21, 12) // date (1980-01-01)
    local.writeUInt32LE(crc, 14)
    local.writeUInt32LE(body.length, 18)
    local.writeUInt32LE(entry.data.length, 22)
    local.writeUInt16LE(name.length, 26)
    local.writeUInt16LE(0, 28)
    locals.push(local, name, body)

    const central = Buffer.alloc(46)
    central.writeUInt32LE(0x02014b50, 0)
    central.writeUInt16LE(20, 4)
    central.writeUInt16LE(20, 6)
    central.writeUInt16LE(0x0800, 8)
    central.writeUInt16LE(method, 10)
    central.writeUInt16LE(0, 12)
    central.writeUInt16LE(0x21, 14)
    central.writeUInt32LE(crc, 16)
    central.writeUInt32LE(body.length, 20)
    central.writeUInt32LE(entry.data.length, 24)
    central.writeUInt16LE(name.length, 28)
    central.writeUInt32LE(0, 42) // offset of the local header
    central.writeUInt32LE(offset, 42)
    centrals.push(central, name)

    offset += local.length + name.length + body.length
  }

  const centralBuffer = Buffer.concat(centrals)
  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(0x06054b50, 0)
  eocd.writeUInt16LE(entries.length, 8)
  eocd.writeUInt16LE(entries.length, 10)
  eocd.writeUInt32LE(centralBuffer.length, 12)
  eocd.writeUInt32LE(offset, 16)
  return Buffer.concat([...locals, centralBuffer, eocd])
}

// ── commands ───────────────────────────────────────────────────────────────

async function cmdList(json: boolean): Promise<void> {
  const logs = await findSessionLogs()
  if (json) {
    process.stdout.write(`${JSON.stringify(logs, null, 2)}\n`)
    return
  }
  if (logs.length === 0) {
    process.stdout.write('no session logs found under $DSH_HOME/sessions\n')
    return
  }
  process.stdout.write(`${logs.length} session(s), newest first:\n\n`)
  for (const log of logs.slice(0, 40)) {
    process.stdout.write(`  ${log.sessionId.slice(0, 28).padEnd(30)} ${(log.bytes / 1048576).toFixed(1).padStart(8)} MiB\n`)
  }
}

async function cmdReport(logArg: string, json: boolean): Promise<void> {
  const path = await resolveLog(logArg)
  const snapshot = await loadSnapshot(path)
  if (json) {
    process.stdout.write(
      `${JSON.stringify(
        {
          path,
          ingest: snapshot.ingest,
          integrity: snapshot.integrity,
          session: snapshot.graph.session,
          usage: snapshot.graph.usage,
          effects: snapshot.effectSummary,
          anomalies: snapshot.graph.anomalies.length,
          files: snapshot.chains.size,
        },
        null,
        2,
      )}\n`,
    )
    return
  }
  process.stdout.write(`${renderSummary(snapshot)}\n`)
}

async function cmdClassify(logArg: string, json: boolean, minSeverity: Severity): Promise<void> {
  const path = await resolveLog(logArg)
  const snapshot = await loadSnapshot(path)
  const payloads = toCompliancePayloads(snapshot.graph)
  const histogram = severityHistogram(payloads)
  const kinds = effectKindTotals(snapshot.effects)

  const flagged = payloads
    .filter((p) => severityRank(p.severity) >= severityRank(minSeverity))
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.ts - b.ts)

  if (json) {
    process.stdout.write(`${JSON.stringify({ path, severity: histogram, effects: kinds, records: flagged }, null, 2)}\n`)
    return
  }

  process.stdout.write(`operations by type (${snapshot.effects.length} effects)\n`)
  for (const [kind, count] of Object.entries(kinds).sort((a, b) => (b[1] ?? 0) - (a[1] ?? 0))) {
    process.stdout.write(`  ${kind.padEnd(12)} ${count}\n`)
  }
  process.stdout.write('\nrisk levels\n')
  for (const s of [...SEVERITIES].reverse()) {
    process.stdout.write(`  ${s.padEnd(9)} ${histogram[s]}\n`)
  }
  process.stdout.write(`\nrecords at ${minSeverity} or above (${flagged.length})\n`)
  for (const record of flagged.slice(0, 30)) {
    process.stdout.write(`  [${record.severity.toUpperCase().padEnd(8)}] ${record.summary.slice(0, 96)}\n`)
    if (record.flags.length > 0) process.stdout.write(`             flags: ${record.flags.join(', ')}\n`)
  }
  if (flagged.length > 30) process.stdout.write(`  … and ${flagged.length - 30} more\n`)
}

function sidecarLines(snapshot: LedgerSnapshot): string {
  const lines: string[] = []
  lines.push(
    JSON.stringify({
      schema: 'dsh-ledger/sidecar/1',
      note: 'facts the compliance schema cannot express: effect fidelity, undecidable shells, version chains',
      generatedAt: Date.now(),
    }),
  )
  for (const effect of snapshot.effects) {
    lines.push(
      JSON.stringify({
        record: 'effect',
        callId: effect.callId,
        tool: effect.toolName,
        turn: effect.turn,
        step: effect.step,
        seq: effect.seq ?? null,
        kind: effect.kind,
        /** exact | partial | observed | undecidable | opaque */
        fidelity: effect.fidelity,
        undecidable: effect.undecidable,
        path: effect.path ?? null,
        contentHash: effect.contentHash ?? null,
        bytes: effect.bytes ?? null,
        command: effect.kind === 'shell' ? (effect.source ?? null) : null,
        detail: effect.detail,
      }),
    )
  }
  for (const chain of snapshot.chains.values()) {
    lines.push(
      JSON.stringify({
        record: 'version-chain',
        path: chain.path,
        created: chain.created,
        preexisting: chain.preexisting,
        contaminated: chain.contaminated,
        shellsInWindow: chain.shellsInWindow,
        lastExactHash: chain.lastExactHash ?? null,
        steps: chain.steps.length,
      }),
    )
  }
  for (const anomaly of snapshot.graph.anomalies) {
    lines.push(
      JSON.stringify({
        record: 'anomaly',
        kind: anomaly.kind,
        turn: anomaly.turn ?? null,
        step: anomaly.step ?? null,
        seq: anomaly.seq ?? null,
        detail: anomaly.detail,
        data: anomaly.data ?? null,
      }),
    )
  }
  return `${lines.join('\n')}\n`
}

function verifyGuide(packName: string, manifest: LedgerManifest): string {
  return `# Verifying this pack

Two independent checks. Neither needs dsh-ledger installed, and the second does not
need the original session log.

## 1. The compliance chain (references dsh-audit-trail)

\`\`\`sh
npm i dsh-audit-trail
node -e "
  const { verifyComplianceJsonl } = require('dsh-audit-trail')
  const fs = require('fs')
  console.log(verifyComplianceJsonl(fs.readFileSync('compliance.jsonl', 'utf8')))
"
\`\`\`

Expected: \`{ valid: true, records: N, issues: [] }\`. Each line is
\`sha256(prevHash + "\\n" + sortedJson({recordId, prevHash, payload}) + "\\n")\`, so any
edited, inserted, removed or reordered record breaks the chain from that point on.

## 2. The Merkle manifest (the original bytes)

\`\`\`sh
node -e "
  const { verifyManifest } = require('@edge-echo/dsh-ledger')
  verifyManifest('<path to the original session.jsonl.zstd>', JSON.parse(require('fs').readFileSync('manifest.json','utf8')))
    .then(r => console.log(r))
"
\`\`\`

Expected: \`{ ok: true }\`. This recomputes two trees over the log — one over each raw
zstd frame, one over each record's bytes — without needing to interpret the content.

| field | meaning |
|---|---|
| \`frameRoot\` | root over ${manifest.frames} raw frame(s) |
| \`recordRoot\` | root over ${manifest.records} record(s), supporting selective disclosure |
| \`bytes\` | ${manifest.bytes} |
| \`signature\` | ${manifest.signature ? 'present — Ed25519 over the manifest' : 'absent (pack was not signed)'} |

## What this pack cannot prove

A shell command's file effects are **not reconstructible from the log**. Those records
carry \`effects-undecidable\` in the compliance file and keep the verbatim command in
\`sidecar.jsonl\`. A file's version chain is marked \`contaminated\` when any shell command
ran between two recorded versions of it. This pack proves *what was recorded and that it
was not altered afterwards*; it does not claim to know what a shell command touched.
`
}

async function cmdPack(logArg: string, out: string, keyPath: string | undefined, title: string): Promise<void> {
  const path = await resolveLog(logArg)
  const snapshot = await loadSnapshot(path)
  const payloads = toCompliancePayloads(snapshot.graph)
  const compliance = complianceJsonl(payloads)

  let manifest: LedgerManifest = await attest(path)
  let signed = false
  if (keyPath) {
    manifest = signManifest(manifest, readFileSync(resolve(keyPath), 'utf8'))
    signed = verifyManifestSignature(manifest)
    if (!signed) die('the signature did not verify after signing; refusing to write a pack that claims to be signed')
  }

  const histogram = severityHistogram(payloads)
  const report = [
    `# ${title}`,
    '',
    `Generated ${new Date().toISOString()} from \`${basename(path)}\`.`,
    '',
    '## What the agent did',
    '',
    '```',
    renderSummary(snapshot),
    '```',
    '',
    '## Risk summary',
    '',
    '| severity | records |',
    '|---|---|',
    ...([...SEVERITIES].reverse().map((s) => `| ${s} | ${histogram[s]} |`)),
    '',
    '## Contents',
    '',
    '| file | what it is |',
    '|---|---|',
    '| `compliance.jsonl` | hash-chained audit records in `dsh-audit-trail/compliance/1` |',
    '| `manifest.json` | Merkle roots over the raw log, ' + (signed ? 'Ed25519-signed' : 'unsigned') + ' |',
    '| `sidecar.jsonl` | effect fidelity, undecidable shell effects, file version chains |',
    '| `REPORT.md` | this file |',
    '| `VERIFY.md` | how to check all of it without this tool |',
    '',
    `Records: ${payloads.length} · Effects: ${snapshot.effects.length} · Files: ${snapshot.chains.size} · Anomalies: ${snapshot.graph.anomalies.length}`,
    '',
  ].join('\n')

  const entries: ZipEntry[] = [
    { name: 'compliance.jsonl', data: Buffer.from(compliance, 'utf8') },
    { name: 'manifest.json', data: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8') },
    { name: 'sidecar.jsonl', data: Buffer.from(sidecarLines(snapshot), 'utf8') },
    { name: 'REPORT.md', data: Buffer.from(report, 'utf8') },
    { name: 'VERIFY.md', data: Buffer.from(verifyGuide(basename(out), manifest), 'utf8') },
  ]

  const target = resolve(out)
  if (target.toLowerCase().endsWith('.zip')) {
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, writeZip(entries))
  } else {
    mkdirSync(target, { recursive: true })
    for (const entry of entries) writeFileSync(join(target, entry.name), entry.data)
  }

  const local = await verifyComplianceWithUpstream(compliance)
  process.stdout.write(`packed ${entries.length} file(s) -> ${target}\n`)
  process.stdout.write(`  compliance records : ${payloads.length} (chain valid: ${local.valid}, verified by ${local.verifier})\n`)
  process.stdout.write(`  risk distribution  : ${[...SEVERITIES].reverse().map((s) => `${s}=${histogram[s]}`).join(' ')}\n`)
  process.stdout.write(`  manifest           : frames=${manifest.frames} records=${manifest.records} signed=${signed}\n`)
  if (!local.valid) {
    process.stdout.write(`  CHAIN PROBLEM: ${local.issues.join('; ')}\n`)
    process.exit(1)
  }
}

async function cmdVerify(target: string, manifestPath: string | undefined, logPath: string | undefined): Promise<void> {
  const resolved = resolve(target)
  let complianceText: string
  try {
    if (statSync(resolved).isDirectory()) {
      complianceText = readFileSync(join(resolved, 'compliance.jsonl'), 'utf8')
    } else if (resolved.toLowerCase().endsWith('.jsonl')) {
      complianceText = readFileSync(resolved, 'utf8')
    } else {
      die('verifying a .zip needs it unpacked first (unzip it, then point this command at the directory)')
    }
  } catch (err) {
    die(`could not read ${resolved}: ${(err as Error).message}`)
  }

  const chain = await verifyComplianceWithUpstream(complianceText)
  process.stdout.write(`compliance chain: ${chain.valid ? 'VALID' : 'INVALID'}\n`)
  process.stdout.write(`  records=${chain.records} lines=${chain.lines} verifier=${chain.verifier}`)
  if (chain.maxSeverity) process.stdout.write(` maxSeverity=${chain.maxSeverity}`)
  process.stdout.write('\n')
  for (const issue of chain.issues.slice(0, 10)) process.stdout.write(`  issue: ${issue}\n`)

  let ok = chain.valid

  const manifestFile =
    manifestPath ?? (statSync(resolved).isDirectory() ? join(resolved, 'manifest.json') : undefined)
  if (manifestFile && statSync(manifestFile).isFile()) {
    const manifest = JSON.parse(readFileSync(manifestFile, 'utf8')) as LedgerManifest
    process.stdout.write(`manifest: schema ok, frames=${manifest.frames} records=${manifest.records}\n`)
    if (manifest.signature) {
      const sigOk = verifyManifestSignature(manifest)
      process.stdout.write(`  signature: ${sigOk ? 'VALID (Ed25519)' : 'INVALID'}\n`)
      ok = ok && sigOk
    } else {
      process.stdout.write('  signature: absent\n')
    }
    if (logPath) {
      const result = await verifyManifest(resolve(logPath), manifest)
      process.stdout.write(`  against ${basename(logPath)}: ${result.ok ? 'MATCHES' : `MISMATCH (${result.mismatch})`}\n`)
      ok = ok && result.ok
    } else {
      process.stdout.write('  (pass --log <session.jsonl.zstd> to recompute the roots)\n')
    }
  }

  process.exit(ok ? 0 : 1)
}

function cmdKeygen(out: string): void {
  const { privateKey } = generateKeyPairSync('ed25519')
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  const target = resolve(out)
  mkdirSync(dirname(target), { recursive: true })
  writeFileSync(target, pem, { mode: 0o600 })
  // Reading it back proves the file is a key this tool can actually use.
  createPrivateKey(pem)
  process.stdout.write(`wrote ${target} (Ed25519). Keep it out of the repo; share the public half.\n`)
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2))
  const json = args.flags.has('json')
  const minSeverity = (flag(args, 'min-severity') ?? 'info') as Severity
  if (!SEVERITIES.includes(minSeverity)) die(`--min-severity must be one of ${SEVERITIES.join('|')}`)

  switch (args.command) {
    case 'list':
      return cmdList(json)
    case 'report': {
      const target = args.positional[0] ?? die('report needs a session log path or id')
      return cmdReport(target, json)
    }
    case 'classify': {
      const target = args.positional[0] ?? die('classify needs a session log path or id')
      return cmdClassify(target, json, minSeverity)
    }
    case 'pack': {
      const target = args.positional[0] ?? die('pack needs a session log path or id')
      const out = flag(args, 'o') ?? flag(args, 'out') ?? die('pack needs -o <out.zip|dir>')
      return cmdPack(target, out, flag(args, 'key'), flag(args, 'title') ?? 'Execution evidence pack')
    }
    case 'verify': {
      const target = args.positional[0] ?? die('verify needs a pack directory or compliance.jsonl')
      return cmdVerify(target, flag(args, 'manifest'), flag(args, 'log'))
    }
    case 'keygen':
      return cmdKeygen(flag(args, 'out') ?? 'ledger-key.pem')
    case '':
    case 'help':
    case '--help':
      process.stdout.write(USAGE)
      return
    default:
      process.stderr.write(`unknown command "${args.command}"\n\n${USAGE}`)
      process.exit(2)
  }
}

main().catch((err: unknown) => {
  process.stderr.write(`fatal: ${(err as Error).message}\n`)
  process.exit(1)
})

export type { Effect }
