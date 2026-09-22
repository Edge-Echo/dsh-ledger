# dsh-ledger

![dsh-ledger](https://raw.githubusercontent.com/Edge-Echo/dsh-ledger/main/banner.svg)

[![npm version](https://img.shields.io/npm/v/@edge-echo/dsh-ledger?color=10b981&logo=npm)](https://www.npmjs.com/package/@edge-echo/dsh-ledger)
[![npm downloads](https://img.shields.io/npm/dm/@edge-echo/dsh-ledger?color=34d399)](https://www.npmjs.com/package/@edge-echo/dsh-ledger)
[![license](https://img.shields.io/badge/license-MIT-6ee7b7)](LICENSE)

**A verifiable execution ledger for [DeepSeek Harness](https://github.com/deepseek-ai) sessions.**

It answers two questions that a session log alone cannot:

1. **What did the agent actually do to this machine?** — turns, steps, tool calls, typed
   effects, file version chains, token cost, and every anomaly worth looking at.
2. **Can you prove that record was not altered afterwards?** — RFC 6962 Merkle trees over the
   raw log, inclusion proofs you can publish, and Ed25519-signed evidence manifests.

Library first, no native dependencies, Node ≥ 22.

---

## Why this is not a `JSON.parse` wrapper

DSH session logs are append-only `session.jsonl.zstd`, and **every append is an independent zstd
frame** — one file is a concatenation of tens of thousands of frames. Node's `zlib` decodes only
the first frame, and its stream API stops there too:

```js
zstdDecompressSync(Buffer.concat([frameA, frameB]))  // => frameA's text only
```

DSH itself works around this with a private zstd handle plus a `koffi` FFI call into libzstd.
`dsh-ledger` takes a different route: it **parses the frame structure** (RFC 8878) to find exact
frame boundaries *without decoding*. That is what makes the properties below possible at all.

| | decode-and-guess | **dsh-ledger** |
|---|---|---|
| find frame boundaries | not possible | structural walk, 34,729 frames in **27 ms** |
| incremental tailing | no | yes, resumable at a byte checkpoint |
| memory | whole file | **1.01×** retained heap at 5× input (measured below) |
| half-written tail frame | corrupts the read | held back, then read once when completed |
| mid-file corruption | aborts the read | resynchronises on the next frame magic |
| tamper evidence | none | Merkle roots + signed manifest |
| native dependencies | koffi + libzstd | none |

---

## Measured on a real session log

Everything below is the output of `npm run verify` against a real 20.05 MiB DSH session log
(34,729 frames, 53,671 records). No synthetic benchmark numbers.

```
1. structural ingestion with bounded memory
    frames=34729 records=53671 bytes=21024791 polls=6 pendingPeak=5233 2449ms (8.2 MiB/s)
  [PASS] read the whole file        [PASS] frames found        [PASS] records parsed
  [PASS] no diagnostics — 0 problems
  [PASS] pending buffer is small — 5233 bytes held back

2. bounded memory (retained heap does not scale with file size)
    reference      20.05 MiB -> 53671 records, retained heap peak 34.63 MiB
    5x scaled     100.25 MiB -> 268355 records, retained heap peak 34.99 MiB
  [PASS] 5x the input does not mean 5x the memory — 100.25 MiB used 1.01x the retained heap

3. checkpoint resume
  [PASS] resume emits no records    [PASS] resume reads no bytes — 0 bytes read

4. independent structural checks
  [PASS] frame count <= magic occurrences — 34729 <= 34729

5. append safety (half-written frame)
  [PASS] complete frames read, partial frame held
  [PASS] checkpoint sits at the partial frame
  [PASS] partial frame read exactly once when completed

6. tamper detection on a real log
  [PASS] flipped byte is detected — 1 diagnostic(s)
  [PASS] tampered log yields fewer or unparsable records — 53670 vs 53671 clean

7. corruption resilience (destroyed frame region)
  [PASS] reading continues past the destroyed region — 6640 records
  [PASS] frames before and after the gap are both recovered — 5479 frames recovered

8. integrity and selective disclosure on real data
  [PASS] clean log verifies against its manifest — all roots reproduce
  [PASS] one flipped byte in 20 MiB is detected
  [PASS] a single record is provable against the published root — proof is 1570 bytes
    disclosure: 1570 bytes of proof (0.0075% of the log) from 53671 records

9. execution graph on real data
    turns=133 calls=1860 paired=1860 errors=72 anomalies=116 files=177
    usage: input=1001273 output=2133150 cacheRead=725243008 reasoning=974409
  [PASS] every tool call is paired with its result — 1860/1860
  [PASS] every tool call yields an effect — 1860/1860
  [PASS] no tool fell through to unknown — 0 unknown
  [PASS] undecidable effects are marked, not guessed — 650 shell effects marked undecidable
  [PASS] shell contamination is reported for affected file chains — 58/177 chains

33/33 checks passed
```

Two cross-checks make those numbers trustworthy rather than self-confirming:

- The **frame count equals the number of frame magics in the file** (34,729 = 34,729), counted by a
  separate linear scan. No false boundaries, no missed frames.
- Every boundary the walker produces is handed to zlib, **which validates each frame's own
  framing and checksum**. A one-byte boundary error anywhere would throw.

---

## Install

```bash
npm install @edge-echo/dsh-ledger
```

> The unscoped name `dsh-ledger` on npm belongs to an unrelated package, so this
> one publishes under the author's scope. The project, the repo and the CLI all
> keep the name `dsh-ledger`; only the install specifier differs.

## Use

### Audit what happened

```js
import { readLedger, renderSummary, findSessionLogs } from '@edge-echo/dsh-ledger'

const [log] = await findSessionLogs()          // newest first, from ~/.dsh/sessions
const ledger = await readLedger(log.path)

console.log(renderSummary(ledger))

ledger.graph.turns.length                       // 133
ledger.graph.calls                              // tool call + result + duration + effects
ledger.effectSummary                            // { edit: 687, shell: 650, read: 262, write: 178, — }
ledger.chains.get('C:\\proj\\out.html')         // version chain: created? contaminated?
ledger.graph.anomalies                          // retries, tool errors, aborts, escalations
```

### Publish evidence, verify it later

```js
import { attest, verifyManifest, signManifest } from '@edge-echo/dsh-ledger'

const manifest = await attest(log.path)
// { sessionId, bytes, frames, records, frameRoot, recordRoot, algorithm: 'sha256/rfc6962' }

const signed = signManifest(manifest, fs.readFileSync('key.pem', 'utf8'))

// — someone else, later, on a machine that never saw the log:
const result = await verifyManifest(suspectPath, signed)
result.ok          // false once any byte has changed, been added or been removed
result.mismatch    // 'frameRoot' | 'recordRoot' | 'bytes' | 'frames' | 'records'
```

### Prove one record without revealing the session

```js
import { buildManifest, MerkleTree, hashLeaf } from '@edge-echo/dsh-ledger'

const { manifest, recordTree, records } = await buildManifest(log.path)
const proof = recordTree.prove(records.findIndex((r) => r.recordType === 'tool/call'))

// Publish: the root, the record count, one record's bytes, and a 1.5 KB proof.
// The other 53,670 records stay confidential.
MerkleTree.verify(proof, hashLeaf(recordBytes), Buffer.from(manifest.recordRoot, 'hex'))
```

### Tail a live session

```js
import { SessionLogTailer } from '@edge-echo/dsh-ledger'

const tailer = new SessionLogTailer(log.path, { from: savedCheckpoint })
for (;;) {
  const batch = await tailer.poll()
  for (const record of batch.records) {
    console.log(record.value.type, `frame ${record.frameIndex} @ ${record.frameStart}`)
  }
  savedCheckpoint = batch.bytesConsumed   // durable: resume exactly here after a crash
  if (batch.atEnd) await new Promise((r) => setTimeout(r, 500))
}
```

---

## Design decisions worth knowing

**Effect fidelity is explicit, never implied.** Every effect carries one of `exact` (a `write`
with its full content), `partial` (an `edit` carries only the replaced fragment), `observed` (the
call proves a path was touched, not what it held) or `undecidable`.

**Shell commands are marked, not guessed.** In the reference session, 650 of 1,860 tool calls were
`pwsh`. A shell command can create, overwrite or delete anything, so inferring its file effects
from the command string would be speculation dressed as evidence. `dsh-ledger` records the command
verbatim, marks the effect `undecidable`, and instead makes the *record of the command* provable.
Consequently a file version chain is flagged `contaminated` when any shell command ran between two
recorded versions of it — on the reference session that is 58 of 177 chains, because it is true.

**Frames are hashed without decompressing.** The frame tree covers raw bytes, so it can attest
content it cannot read, and it costs no zstd work.

**RFC 6962 hashing, not the naive tree.** Leaves are `SHA-256(0x00 — data)`, internal nodes
`SHA-256(0x01 — left — right)`. The domain separation stops an internal node being replayed as a
leaf — a forgery the common "promote the odd node" construction allows.

**Library, not a plugin — deliberately.** The integrity format and the graph API are what other
tools should build on; a DSH tool wrapper is a thin layer that will be added once the API has
proven stable. `package.json` ships no `dsh` bundle entry.

---

## Known limitations

- **Decode throughput is ~8 MiB/s single-threaded**, because Node creates a fresh zstd context per
  `zstdDecompressSync` call (~45 µs/frame at ~1.9 KB per frame). Structural walking is 27 ms for
  the same file; only decoding is slow. Measured 2.0× with 4 worker threads over a
  `SharedArrayBuffer`, which is not wired in yet. Integrity work needs no decode at all.
- **Shell effect attribution is undecidable by construction** (see above). Closing that gap needs
  sandbox-level file monitoring, not log analysis.
- **`edit` effects are `partial` fidelity.** The log contains the replaced and replacement text,
  not the surrounding file, so a whole-file digest cannot be claimed for an edited file.
- **Paths are resolved against the session cwd and compared case-insensitively on Windows**;
  symlinks and directory junctions are not resolved.
- **A log is only ever attested as it exists now.** Appending to a log after a manifest was signed
  invalidates that manifest — which is the intended behaviour, not a bug.
- **`--expose-gc` is required** for the retained-heap measurement in `npm run verify`; other
  checks run without it.

---

## Verification

```bash
npm run build     # tsc
npm test          # 28 tests: frame walker, tailer, Merkle, effects, graph, end-to-end
npm run verify    # 33 acceptance checks against a real session log
npm run check     # all three
```

`npm run verify` discovers the largest log under `$DSH_HOME/sessions` (override with
`DSH_LEDGER_LOG`). Set `DSH_LEDGER_TEST_LOG` to include the real-log test in `npm test`.

The test suite attacks the implementation rather than confirming it: every leaf of every tree size
from 1 to 33 (the sizes where split rules break), a node hash presented as a leaf, a one-byte
change in each leaf, a same-length frame reordering, a truncated log, an appended frame, and a
tampered signed manifest.

## License

MIT

