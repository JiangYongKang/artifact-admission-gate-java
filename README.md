# Artifact Admission Gate（离线制品准入校验）

以本地文件模拟制品、签名、来源证明（Provenance）与**软件成分清单（SBOM）**，对制品执行
**摘要 + 签名 + 来源证明 + 软件成分清单** 的联合校验，在任意信任策略与异常输入下给出
一致、可区分、可追溯的准入结论。信任根与策略支持**运行期治理**（新增/轮换/撤销/下线，
发布即生效，无需重启），既有结论在信任或策略变化后**按最新状态重新复核**。
全程仅依赖 JDK 与 Spring Boot，不访问任何外部服务，不使用真实凭据。

## 信任模型与配置版本

```
制品内容(Base64) ──SHA-256──> 计算摘要 ──比对──> 声明摘要
声明摘要 ──Ed25519 验签(签名者公钥)──> 签名有效性
来源证明(ProvenanceStatement) ──绑定(artifactId+摘要)──> 制品
来源证明 ──Ed25519 验签(证明者公钥)──> 证明可信性
软件成分清单(SoftwareBillOfMaterials) ──绑定(artifactId+摘要)+Ed25519 验签+组件范围──> 成分合规
配置快照(ConfigurationSnapshot: 信任根 + 策略, 单调版本) ──一次判定固定一版──> 结论带 configVersion
```

- 密钥仅持有**公钥**；私钥材料不进入系统，日志与对外响应只出现 `keyId`。
- `GovernanceManager` 是唯一的配置写入口：所有变更经同一把锁串行化，成功变更使配置版本
  严格递增并**原子发布**为新的不可变快照（volatile 引用 + 不可变 Map/List）。
- 准入请求在入口固定一份快照，随后所有阶段（策略/密钥/证明/SBOM）只读该快照，
  **不会出现一半旧配置、一半新配置**；同一版本快照下不同请求结论一致。
- 幂等键为 `请求规范化哈希#v配置版本`：同版本下重复（含并发）提交归并为同一条记录；
  配置变更后同一制品键不同，按最新配置重新判定。

## 运行期配置治理

通过 `POST /api/governance/**` 在运行过程中管理，改动对之后进来的请求**立即生效**：

| 操作 | 接口 | 冲突/非法响应 |
|---|---|---|
| 新增密钥 | `POST /api/governance/keys` | keyId 已存在 → 409 `KEY_CONFLICT`；公钥编码非法 → 400 |
| 轮换密钥 | `POST /api/governance/keys/rotate` | 旧密钥不存在 → 409 |
| 撤销 / 过期密钥 | `POST /api/governance/keys/{id}/revoke`、`/expire` | 密钥不存在 → 409 |
| 发布策略 | `POST /api/governance/policies` | 见下，400/409 |
| 替换策略 | `PUT /api/governance/policies/{id}` | 目标不存在 → 409 |
| 下线策略 | `DELETE /api/governance/policies/{id}` | 目标不存在 → 409 |
| 查看当前版本 | `GET /api/governance/snapshot` | 只回 keyId/状态与策略 ID，不含密钥材料 |

密钥请求体中的公钥为 Base64 的 X.509 SubjectPublicKeyInfo（可用
`TestFixtures.publicKeyX506Base64` 在本地生成，纯本地模拟）。

**发布阶段即拒绝非法策略**，绝不拖到请求进来才失败：

- 制品标识正则不可编译 → 400 `POLICY_INVALID`；
- 同优先级策略的制品覆盖范围重叠（null 匹配全部必然重叠；正则文本相同重叠），
  会造成同一制品有多条最高优先级命中 → 400 `POLICY_INVALID`；
- 策略 ID 重复发布 → 409 `POLICY_CONFLICT`；
- 策略引用了当前信任库中**不存在、已撤销或已过期**的签名/SBOM 密钥
  → 400 `POLICY_KEY_UNTRUSTED`。

  复杂正则的交集不做静态求解，但请求期仍会检测同优先级多命中并**失败关闭**
  （`POLICY_CONFLICT`），构成纵深防线。空允许列表语义不变：显式禁止一切。

## 软件成分清单（SBOM）

`SoftwareBillOfMaterials` 含 `billId / artifactId / artifactDigest / components /
signerKeyId / signature`，签名载荷规范化为
`billId|artifactId|artifactDigest|name@version,...`。放行前必须确认清单**确实属于该制品**：

| 检查 | 失败原因 |
|---|---|
| 策略要求清单但未提供 | `SBOM_MISSING` |
| 清单 artifactId 或摘要与实际制品不符 | `SBOM_NOT_BOUND` |
| 清单签名者不在策略允许的 SBOM 签名者内 | `SBOM_UNTRUSTED` |
| 清单密钥缺失/撤销/过期或签名验不过 | `SBOM_UNTRUSTED` / `KEY_REVOKED` / `KEY_EXPIRED` |
| 组件超出策略允许范围 | `SBOM_COMPONENT_NOT_ALLOWED` |

策略新增维度（均保持"null 不限制，空列表禁止一切"的约定）：
`requireSbom`、`allowedComponents`（`name` 或 `name:version` 精确匹配）、
`allowedSbomSignerKeyIds`（null 表示信任库内任意有效密钥）。
四类清单失败原因彼此分开，不会笼统丢一个失败。

## 结论复核与证明归属

- **密钥撤销/过期后复核翻转**：已放行的制品在其签名密钥或证明密钥被撤销/过期后再次提交，
  立即得到 `KEY_REVOKED`/`KEY_EXPIRED` 等新结论；新记录带新 `configVersion`，
  旧记录保留可追溯（`GET /api/admissions/{旧recordId}` 仍是原结论），但不会被当当前结论端回。
- **更高优先级新策略即时生效**：发布更严格的高优先级（数值更小）策略后，
  同一制品按新策略判定（如 `BUILDER_NOT_ALLOWED`）。
- **来源证明不可挪用**：`ReplayGuard` 记录每份 statementId 的归属
  （artifactId+摘要+原始 recordId）。证明被挪到别的制品：
  - 绑定对不上 → `PROVENANCE_NOT_BOUND`；
  - 被重新签名绑定到别的制品摘要 → `PROVENANCE_REPLAYED`，返回**非持久化归属视图**，
    `attributedRecordId` 指向原本那条结论，视图 recordId 为 `attribution:{原始id}`，
    不占新记录、不可作为独立记录查询。
  - 同一制品带着自己原来的证明在配置变更后再次提交：**不是重放**，按最新配置复核。

## 校验流水线与拒绝原因

按固定顺序判定，任一阶段失败即定终态，原因可区分：

| 顺序 | 检查 | 失败原因 |
|---|---|---|
| 1 | 内容摘要 vs 声明摘要 | `DIGEST_MISMATCH` |
| 2 | 策略选择（缺失/冲突）与密钥引用 | `POLICY_MISSING` / `POLICY_CONFLICT` / `UNTRUSTED_KEY` |
| 3 | 策略约束（签名者、构建来源） | `SIGNER_NOT_ALLOWED` / `BUILDER_NOT_ALLOWED` |
| 4 | 制品签名（密钥状态 + 验签） | `UNTRUSTED_KEY` / `KEY_REVOKED` / `KEY_EXPIRED` / `SIGNATURE_INVALID` |
| 5 | 来源证明（绑定/挪用归属/签名/同制品复核） | `PROVENANCE_MISSING` / `PROVENANCE_NOT_BOUND` / `PROVENANCE_UNTRUSTED` / `PROVENANCE_REPLAYED` |
| 6 | 软件成分清单（存在/绑定/签名/成分） | `SBOM_MISSING` / `SBOM_NOT_BOUND` / `SBOM_UNTRUSTED` / `SBOM_COMPONENT_NOT_ALLOWED` |

记录状态只有 `PENDING`（批量窗口内短暂存在）、`ADMITTED`、`REJECTED` 三种；
持久化记录结论不可变，归属视图标记 `attributedRecordId` 且不落库。

## 密钥轮换、撤销与过期

- **轮换**：旧密钥转为 `RETIRED` 并记录退役时刻；退役时刻**之前**签发的签名在宽限规则下
  仍有效，之后的一律拒绝（`KEY_EXPIRED`）。
- **撤销** `revoke`：该密钥的任何签名立即失效（`KEY_REVOKED`），含历史签名。
- **过期** `expire` 或超过 `notAfter`：一律拒绝（`KEY_EXPIRED`）。

## 并发与批量

- Store / TrustStore / PolicyEngine / GovernanceManager / ReplayGuard 均线程安全；
  配置写入在治理管理器锁内串行，读取为不可变快照，准入判定过程无共享可变状态。
- 同一请求并发提交解析为**同一条记录**（先写记录再发布索引）。
- 批量上限：`admission.batch.max-size`（默认 100）与 `admission.batch.max-duration-ms`（默认 5000）。
  规模超限**整批拒绝**不落记录；耗时超限剩余项以 `BATCH_LIMIT_EXCEEDED` 明确拒绝，
  每条记录均为完整终态。

## 对外接口

- `POST /api/admissions` / `POST /api/admissions/batch` / `GET /api/admissions/{recordId}`
  （原有，行为保持；单条记录新增 `configVersion` 与可空 `attributedRecordId` 字段，
  向后兼容）。
- `POST/PUT/DELETE/GET /api/governance/**`（本轮新增，见"运行期配置治理"）。

## 兼容范围

- 入参/模型保持向后兼容：无 SBOM 的旧请求使用 6 参构造；旧策略使用无 SBOM 维度的构造；
  旧的直接持有 `TrustStore`/`PolicyEngine` 装配方式经 `LiveConfigurationRegistry`
  适配器仍可工作（快照锁序与治理管理器一致）。
- 全部加密使用 JDK 内置 Ed25519/SHA-256，密钥对在测试中本地即时生成，
  不接外部服务、不用真实凭据。

## 本地复现与验证

```bash
mvn -o test               # 离线运行全部测试（45 个用例）
mvn -o spring-boot:run    # 本地启动服务，然后用 curl 调 /api/governance 与 /api/admissions
```

测试覆盖（在原有 19 个场景不回归的基础上新增）：

- 运行期新增密钥即时生效、重复注册/撤销未知密钥拒绝；
- 策略发布期拒绝：引用不受信任密钥、同优先级矛盾、非法正则、重复 ID、替换不存在策略；
- 更高优先级策略即时改变结论；下线唯一策略后失败关闭；
- 撤销/过期后已放行制品复核翻转、旧记录仍可追溯；
- 证明挪用归属原结论（不产生新记录）、同制品配置变更后按新结论复核而非重放；
- SBOM：缺失、摘要不符、artifactId 不符、伪造签名、签名者越权、组件越界、合法清单放行；
- 并发判定与配置变更同时进行，结论均绑定某一具体配置版本且同版本一致；
- 治理 HTTP 接口 201/200/400/409 与快照内容。

每个用例日志打印 **输入摘要、配置版本与判定依据**
（`inputDigest=... configVersion=... basis=...`），输出重定向到
`target/surefire-reports/*-output.txt`，出问题时可直接对照。
