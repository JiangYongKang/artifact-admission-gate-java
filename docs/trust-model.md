# 离线制品准入校验 — 信任模型说明

本服务在**完全离线**条件下，对“制品 + 制品签名 + 来源证明（provenance）+ 软件成分清单（SBOM）”
做联合准入校验。制品、签名、证明、SBOM 均以**本地文件**模拟；信任根公钥、策略与准入记录全部保存在
进程内存中。不依赖任何外部服务、真实凭据或网络资源。

---

## 1. 数据模型（本地文件模拟）

| 对象 | 形式 | 关键字段 |
|------|------|----------|
| 制品 artifact | 任意本地文件 | 以 SHA-256 摘要标识 |
| 制品签名 signature | JSON 信封文件 | `keyId`、`signedDigest`、`algorithm`、`signedAt`、`signatureBase64` |
| 来源证明 attestation | JSON 文件 | `statementId`（重放键）、`artifactDigest`（绑定）、`sbomDigest`、`claims{buildSource, artifactId}`、`issuedAt`、内嵌签名信封 |
| SBOM | 任意本地文件（可选） | 提交时必须与证明中的 `sbomDigest` 一致 |
| 信任根 | 内存 + 可选目录引导 | `keyId`、RSA 公钥、`state`、`expiresAt`、`rotatedAt`、`replacedKeyId` |
| 信任策略 | 内存 + 可选目录引导 | `policyId`、规则列表 |

密码学仅使用 JDK 内置能力：摘要 `SHA-256`，签名 `SHA256withRSA`（2048 位测试密钥，运行时生成）。
来源证明的“被签名内容”是其载荷字段拼接后的 SHA-256，签名字段本身不参与自身摘要，避免自引用。

## 2. 准入状态机（不存在不可解释中间态）

```
提交 ──► PENDING（仅在同一 statementId 锁内短暂存在）──► ADMITTED
                                                  └──► REJECTED(+原因码)
```

- 提交接口**同步**给出终态；外部任何时刻通过查询接口拿到的都是 `ADMITTED` 或 `REJECTED`。
- `PENDING` 只存在于“建记录 → 判终态”这一持锁事务窗口内，且该记录在创建时就已绑定**制品摘要**。
- 查询不存在的 id 返回明确的 `404 NOT_FOUND`，绝不返回含义不明的状态。
- 拒绝是明确的业务终态（HTTP 200，正文 `status=REJECTED`），区别于请求/系统错误（4xx/5xx）。

### 拒绝原因码（全部可区分）

`DIGEST_MISMATCH`、`SIGNATURE_INVALID`、`ATTESTATION_MISSING`、`ATTESTATION_NOT_BOUND`、
`ATTESTATION_MALFORMED`、`KEY_UNTRUSTED`、`KEY_REVOKED`、`KEY_EXPIRED`、`KEY_SUPERSEDED`、
`POLICY_MISSING`、`POLICY_CONFLICT`、`POLICY_DENIED`、`SBOM_DIGEST_MISMATCH`、
`BATCH_TOO_LARGE`、`BATCH_TIMEOUT`、`BAD_REQUEST`。

## 3. 联合校验链（顺序固定，任一失败即失败关闭）

1. **制品摘要**：实算 SHA-256，与请求声称摘要不一致 → `DIGEST_MISMATCH`。
2. **制品签名信封**：缺失/损坏/字段不全 → `SIGNATURE_INVALID`。
3. **签名密钥信任状态**：见第 4 节，产出 `KEY_*`。
4. **制品签名密码学验证**：信封 `signedDigest` 必须等于实算摘要，且 RSA 验签通过，否则 `SIGNATURE_INVALID`。
5. **来源证明存在性**：文件缺失 → `ATTESTATION_MISSING`；存在但不可解析 → `ATTESTATION_MALFORMED`。
6. **证明与制品绑定**：证明 `artifactDigest` 必须等于制品实算摘要，否则 `ATTESTATION_NOT_BOUND`。
7. **证明签名密钥与验签**：信任状态 + RSA 验签（`KEY_*` / `SIGNATURE_INVALID`）。
8. **SBOM 绑定**（仅在随请求提交时）：实算摘要必须等于证明声明的 `sbomDigest`，否则 `SBOM_DIGEST_MISMATCH`。
9. **策略判定**：见第 5 节。

## 4. 信任根模型与轮换 / 撤销 / 过期规则

密钥状态：`ACTIVE`、`ROTATED`、`REVOKED`，外加可配的 `expiresAt`。

| 情形 | 判定 | 规则 |
|------|------|------|
| 密钥未登记 | `KEY_UNTRUSTED` | 引用不可信密钥一律失败关闭 |
| `REVOKED` | `KEY_REVOKED` | **对历史签名同样生效**，撤销不可被旧时间戳豁免 |
| `now >= expiresAt` | `KEY_EXPIRED` | 过期密钥不得再通过任何校验 |
| `ROTATED` 且 `signedAt < rotatedAt` | 通过 | **轮换前的旧签名在轮换后仍有效** |
| `ROTATED` 且 `signedAt >= rotatedAt` | `KEY_SUPERSEDED` | 轮换时间点之后不得再用旧根签发 |
| `ACTIVE` 且未过期 | 通过 | — |

- 轮换操作在同一同步流程内“注册新根 + 将旧根置为 `ROTATED` 并记录 `replacedKeyId`”，不产生半更新。
- 撤销即时生效，并会影响**重放复核**（见第 6 节）。
- 密钥材料（公钥 PEM、私钥、签名原文）**只存在内存/本地临时文件中**，不出现在任何日志或对外响应里；
  对外只暴露 `keyId`（标识符，非材料）。

## 5. 信任策略与优先级

一条策略由若干规则组成：`(id, constraint∈{SIGNER, BUILD_SOURCE, ARTIFACT_ID}, value, effect∈{ALLOW,DENY}, precedence)`。

判定规则（`PolicyEvaluator`）：

1. 按三个约束维度分别处理；事实来源：
   - `SIGNER` = 制品签名信封的 `keyId`
   - `BUILD_SOURCE` / `ARTIFACT_ID` = 来源证明 `claims`
2. 每个维度只保留**命中事实**且 `precedence` 最高的规则（**明确优先级**）。
3. 任一维度最高优先级为 `DENY` → 拒绝 `POLICY_DENIED`；三个维度全部 `ALLOW` 才放行。
4. 某维度事实缺失或没有任何规则命中 → 拒绝 `POLICY_DENIED`（**无匹配默认拒绝，绝不默认放行**）。
5. 同一“维度+取值”上存在两条**相同 precedence、相反 effect**的规则 → 无法用优先级消歧，
   在**策略发布时**即判 `POLICY_CONFLICT`，策略整体不生效，旧版本保持不变（失败关闭）。
6. 引用不存在的策略 → `POLICY_MISSING`；空策略/无规则策略在配置时即 `POLICY_MISSING`。

策略库以“先整体校验、后整体发布”的方式写入；并发读取永远只能看到某个完整一致的版本。

## 6. 重放防护

- 以证明的 `statementId` 作为幂等键，仓库为每个 statementId 维护一把锁，
  同一证明的并发/重复提交被串行化，**全程只产生一条准入记录**。
- 重复提交不会新建记录，只累加 `replayCount`，响应中 `replay=true`。
- 每次重放都会用**当前**信任根与策略重新完整复核：
  - 历史结论是 `REJECTED` → 永久维持拒绝（即使策略后来放宽），重放**不得绕过已生效的拒绝**；
  - 历史结论是 `ADMITTED` 但密钥此后被撤销/过期 → 记录翻转为 `REJECTED`（可追溯的重放复核轨迹）。

## 7. 并发一致性

- 准入记录、statementId 索引、审计日志均使用并发结构；记录状态迁移在对象锁内完成。
- 同一 statementId：`computeIfAbsent` 惰性 per-key 锁，保证“查重→建 PENDING→判终态”原子。
- 不同 statementId 使用不同锁，保证吞吐。
- 策略读取为不可变快照引用；信任根轮换/撤销在 `synchronized` 方法内整体替换条目。
- 审计使用追加式 `CopyOnWriteArrayList`，不会出现半更新或结果串号。

## 8. 批量规模 / 耗时上限与回滚

- 规模上限 `admission.gate.batch-max-items`（默认 50）：超限立即整体拒绝 `BATCH_TOO_LARGE`，不触碰任何状态。
- 耗时上限 `admission.gate.batch-time-budget-millis`（默认 2000ms）：逐项处理，超预算即停止并返回
  `BATCH_TIMEOUT`，并**回滚本批次新建的全部准入记录与 statementId 索引**；重放命中的既有记录不会被删除。
- 顺序处理、不引入需要额外清理的线程池资源，避免资源泄漏与部分状态残留。
- 批次内逐条结论都可在结果中追溯；仅当每条都 `ADMITTED` 时批次整体标记放行。

## 9. 审计可追溯性

每条审计事件记录：时间、admissionId、statementId、**输入制品摘要**、状态迁移（from→to）、
拒绝原因码、判定依据（命中的规则 id/优先级、各步结论）。**不记录**任何密钥或签名材料。
测试日志同样打印“输入摘要 + 判定依据”，满足自动化验证与人工复核。

## 10. 配置项（`application.properties`，均可省略）

```
admission.gate.trust-dir=<本地信任根目录，可选；缺省=空信任库(失败关闭)>
admission.gate.policies-dir=<本地策略 JSON 目录，可选；缺省=空策略库(失败关闭)>
admission.gate.batch-max-items=50
admission.gate.batch-time-budget-millis=2000
```

信任根目录布局：`<trustDir>/<keyId>/public.pem` + 可选 `meta.json`
（`state`、`expiresAt`、`rotatedAt`、`replacedKeyId`）。策略目录下每个 `*.json` 即一个 `TrustPolicy`。
引导期任一密钥/策略装载失败都会失败关闭，拒绝以“半套信任根”启动。
