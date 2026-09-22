# Changelog

## 0.1.0

First release. Library only — no DSH plugin bundle yet, by design: the integrity format and graph
API are what other tools should depend on, and they are cheaper to stabilise before wrapping.

Published as **`@edge-echo/dsh-ledger`**: the unscoped name `dsh-ledger` on npm belongs to an
unrelated package, so this publishes under the author's scope. The project, repo and CLI keep the
name `dsh-ledger`.

**Frame layer** (`frames.ts`)
- Structural zstd frame walker (RFC 8878): frame header descriptor, window descriptor, dictionary
  id, content size, block headers, skippable frames. Finds exact frame boundaries with no decode.
- Returns `incomplete` instead of throwing when a writer is mid-append, and `corrupt` with a
  resynchronisation point rather than aborting on a damaged region.

**Reader** (`reader.ts`)
- Incremental, crash-safe tailer with a resumable byte checkpoint (`bytesConsumed`).
- Bounded memory: one frame decoded at a time; partial tail frames held back until completed.
- A record that straddles a frame boundary is reassembled, and the checkpoint stays behind the
  frame it came from so a restart replays rather than truncates it.
- Configurable read-ahead; a frame exceeding `maxFrameBytes` is treated as a corrupt region
  instead of growing without bound.

**Execution graph** (`graph.ts`)
- Turns, steps, tool calls paired with their results by `callId`, per-turn and per-model token
  usage (deduplicated across retry re-emits), initial vs final governance state, and anomalies:
  `llm-retry`, `tool-error`, `compaction`, `turn-aborted`, `approval-asked`, `approval-denied`,
  `permission-change`, `unpaired-tool-call`, `orphan-tool-result`.
- Streaming delta records are counted, not retained.

**Effect attribution** (`effects.ts`)
- Typed effects per tool call with explicit `fidelity`: `exact`, `partial`, `observed`,
  `undecidable`.
- Shell commands are recorded verbatim and marked `undecidable` — their file effects are not
  reconstructible, and guessing them would turn evidence into speculation.
- Per-path version chains with `created` / `preexisting` classification and `contaminated`
  flagging when a shell command ran between two recorded versions of a path.

**Integrity** (`merkle.ts`)
- RFC 6962 Merkle trees with `0x00`/`0x01` domain separation, over frame bytes and over record
  bytes; inclusion proofs; selective disclosure of one record without revealing the rest.
- Signed evidence manifests (Ed25519 via `node:crypto`), canonical JSON so signatures do not
  depend on key order, and `verifyManifest` that reports which root diverged.

**Verified on a real 20.05 MiB session log**: 34,729 frames, 53,671 records, 133 turns, 1,860 tool
calls all paired and all attributed, 116 anomalies, 177 file chains. Retained heap at 5× the input
is 1.01× the reference. Frame count independently cross-checked against a magic-byte scan; every
boundary validated by zlib's own frame checksum.
