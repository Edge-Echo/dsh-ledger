# dsh-ledger

![dsh-ledger](https://raw.githubusercontent.com/Edge-Echo/dsh-ledger/main/banner.svg)

[![npm version](https://img.shields.io/npm/v/@edge-echo/dsh-ledger?color=10b981&logo=npm)](https://www.npmjs.com/package/@edge-echo/dsh-ledger)
[![npm downloads](https://img.shields.io/npm/dm/@edge-echo/dsh-ledger?color=34d399)](https://www.npmjs.com/package/@edge-echo/dsh-ledger)

**可验证的 DeepSeek Harness 执行账本。** 回答单纯看会话日志回答不了的两个问题：

1. **Agent 到底对这台机器做了什么？** —— turn/step/工具调用/类型化效应/文件版本链/token 成本，以及所有值得一看的异常。
2. **事后能不能证明这条记录没被改过？** —— 对原始日志做 RFC 6962 Merkle 树、可对外发布的存在性证明、Ed25519 签名的证据清单。

库优先（library-first），**零原生依赖**，Node ≥ 22。

---

## 为什么这不是"包一层 JSON.parse"

DSH 的会话日志是 append-only 的 `session.jsonl.zstd`，而**每一次 append 都是一个独立的 zstd 帧**——一个文件就是几万个帧的拼接。Node 的 `zlib` 只能解出第一个帧，流式 API 也一样：

```js
zstdDecompressSync(Buffer.concat([frameA, frameB]))  // 只会返回 frameA 的文本
```

DSH 官方自己是用「私有 zstd handle + koffi FFI 调 libzstd」绕过去的。`dsh-ledger` 换了一条路：**直接解析帧结构**（RFC 8878）来定位精确的帧边界，**完全不解压**。下面这些能力全都建立在这上面。

| | 解压再猜边界 | **dsh-ledger** |
|---|---|---|
| 找帧边界 | 做不到 | 结构化遍历，34,729 帧仅 **27 ms** |
| 增量读取 | 不支持 | 支持，可从字节检查点续读 |
| 内存 | 整个文件 | 输入放大 5 倍，驻留堆 **1.01 倍**（实测） |
| 写一半的尾帧 | 读坏 | 暂存，写完后再读一次且只读一次 |
| 文件中部损坏 | 直接中断 | 跳到下一个帧魔数继续 |
| 篡改证据 | 无 | Merkle 根 + 签名清单 |
| 原生依赖 | koffi + libzstd | 无 |

---

## 真实会话实测数据

以下全部是 `npm run verify` 在一个真实 20.05 MiB DSH 日志（34,729 帧 / 53,671 条记录）上的输出，**不是合成跑分**：

```
1. structural ingestion with bounded memory
    frames=34729 records=53671 bytes=21024791 polls=6 pendingPeak=5233 2449ms (8.2 MiB/s)

2. bounded memory (retained heap does not scale with file size)
    reference      20.05 MiB -> 53671 records, retained heap peak 34.63 MiB
    5x scaled     100.25 MiB -> 268355 records, retained heap peak 34.99 MiB
  [PASS] 5x the input does not mean 5x the memory — 100.25 MiB used 1.01x

3. checkpoint resume        [PASS] resume reads no bytes — 0 bytes read
4. independent checks       [PASS] frame count <= magic occurrences — 34729 <= 34729
6. tamper detection         [PASS] flipped byte is detected
7. corruption resilience    [PASS] frames before and after the gap are both recovered — 5479 frames

8. integrity and selective disclosure on real data
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

两个**独立交叉验证**让这些数字不是自证：

- **帧数恰好等于文件里帧魔数出现的次数**（34,729 = 34,729），用另一套线性扫描单独数出来的。既没有假边界，也没有漏帧。
- 遍历器给出的每一个边界都交给 zlib，**由 zlib 校验每个帧自身的框架和校验和**。边界错一个字节就会抛异常。

---

## 安装与使用

```bash
npm install @edge-echo/dsh-ledger
```

> npm 上不带 scope 的 `dsh-ledger` 属于另一个无关的包，因此本项目发布在作者 scope 下。
> 项目名、仓库名与命令行都仍叫 `dsh-ledger`，只有安装名不同。

```js
import { readLedger, renderSummary, findSessionLogs, attest, verifyManifest } from '@edge-echo/dsh-ledger'

const [log] = await findSessionLogs()        // 最新的在前
const ledger = await readLedger(log.path)
console.log(renderSummary(ledger))

ledger.graph.calls          // 工具调用 + 结果 + 耗时 + 效应
ledger.effectSummary        // { edit: 687, shell: 650, read: 262, write: 178, … }
ledger.chains               // 每个文件的版本链：新建？已被 shell 污染？

const manifest = await attest(log.path)      // 对外发布的证据清单
const result = await verifyManifest(suspectPath, manifest)
result.ok        // 任何一个字节被改/被增/被删都会变成 false
```

---

## 值得知道的设计取舍

**效应保真度是显式标注的，绝不隐含。** 每个效应都带 `exact`（`write` 有完整内容）、`partial`（`edit` 只有被替换的片段）、`observed`（只能证明这个路径被碰过）、`undecidable` 之一。

**shell 命令只标注、不猜测。** 参考会话里 1,860 次调用中有 650 次是 `pwsh`。一条 shell 命令能创建、覆盖、删除任何东西——从命令字符串去推断它的文件效应，那是把猜测包装成证据。所以 `dsh-ledger` 原样记录命令、把效应标为 `undecidable`，转而让**"这条命令被记录过"本身**变得可证明。因此当某文件的两次记录版本之间有 shell 命令跑过时，版本链会被标为 `contaminated`——参考会话是 177 条里的 58 条，因为这是事实。

**帧的哈希不需要解压。** 帧树覆盖的是原始字节，所以它能对"自己读不懂的内容"作证，且不花任何 zstd 开销。

**用 RFC 6962，不用朴素 Merkle。** 叶子是 `SHA-256(0x00 ‖ data)`，内部节点是 `SHA-256(0x01 ‖ left ‖ right)`。这个域分隔阻止了"把内部节点冒充成叶子"的伪造——那是常见的"奇数节点直接上提"构造允许的攻击。

**刻意做成库而不是插件。** 完整性格式和图谱 API 才是别的工具该依赖的东西；DSH 工具壳是薄薄一层，等 API 稳定后再加。`package.json` 里没有 `dsh` bundle 入口。

---

## 已知局限（如实列出）

- **解码吞吐约 8 MiB/s（单线程）**：Node 每次 `zstdDecompressSync` 都会新建 zstd 上下文（约 1.9 KB/帧 → 每帧 ~45 µs）。同样的文件结构化遍历只要 27 ms，慢的只是解码。用 4 个 worker 线程走 `SharedArrayBuffer` 实测 **2.0×**，尚未接入。完整性工作完全不需要解码。
- **shell 的效应归因在原理上不可判定**（见上）。补这个洞需要沙箱级的文件监控，不是日志分析能解决的。
- **`edit` 是 `partial` 保真度**：日志里有被替换文本和替换文本，但没有文件其余部分，所以不能声称编辑后文件的整体摘要。
- **路径按会话 cwd 解析，Windows 上大小写不敏感比较**；不解析符号链接与目录联接。
- **清单只对"当时的日志"作证**：签名之后再 append 会让清单失效——这是设计意图，不是缺陷。
- **`npm run verify` 的驻留堆测量需要 `--expose-gc`**，其余检查不需要。

---

## 验证

```bash
npm run build     # tsc
npm test          # 28 项测试
npm run verify    # 33 项真实数据验收
npm run check     # 三件一起跑
```

测试的方向是**攻击实现**而不是确认实现：对 1..33 每种树大小的每个叶子做证明验证（分裂规则最容易错的尺寸）、把内部节点冒充叶子、每个叶子改一个字节、同长度帧换序、截断日志、追加帧、篡改已签名清单。

## 许可证

MIT
