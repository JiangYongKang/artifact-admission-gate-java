# Artifact Admission Gate（离线制品准入校验）

以本地文件模拟制品、签名、来源证明（Provenance）与软件成分清单（SBOM），对制品执行
**摘要 + 签名 + 来源证明 + 软件成分清单** 的联合校验，在任意信任策略与异常输入下给出
一致、可区分、可追溯的准入结论。全程仅依赖 JDK 与 Spring Boot，不访问任何外部服务、不使用真实凭据。

## 本轮新增能力

1. **运行期配置治理**：信任根（密钥）与策略都能在服务运行过程中新增、轮换、撤销、过期，
   以及发布、同 ID 替换、下线；改动对之后进来的请求**立即生效，无需重启**。
   自相矛盾或引用当前未受信密钥的策略在**发布阶段**就被拒绝（HTTP 422），治理状态保持不变。
2. **软件成分清单校验**：本地文件模拟的 SBOM 被纳入判定。策略可强制要求清单、可限定允许出现的
   组件范围；清单缺失、清单与制品对不上、组件越界分别给出可区分的拒绝原因；
   放行前必须确认清单确实属于这份制品（artifactId + 摘要双重绑定）。
3. **结论复核（Re-evaluation）**：此前已放行的制品，在其依赖的密钥被撤销/过期、或命中更新的
   更高优先级策略后，再次提交会**按当时最新的信任与政策状态重新判定**，绝不把库里的旧结论直接端回。
   结论变化时追加一条修订记录（`revision` 递增、`supersedesRecordId` 串联），历史结论保留可查。
4. **证明重放归属**：同一条来源证明被挪到别的制品上重复使用时，不会产生新的准入记录，
   而是**归回它原本对应的那条结论**。

## 信任模型与治理快照

```
制品内容(Base64) ──SHA-256──> 计算摘要 ──比对──> 声明摘要
声明摘要 ──Ed25519 验签(签名者公钥)──> 签名有效性
来源证明(ProvenanceStatement) ──绑定(artifactId+摘要)──> 制品
来源证明 ──Ed25519 验签(证明者公钥)──> 证明可信性
成分清单(ComponentManifest) ──绑定(artifactId+摘要)+组件范围──> 制品
治理注册表(GovernanceRegistry) ──原子发布不可变快照 GovernanceSnapshot(version, keys, policies)
```

- 密钥仅持有**公钥**；私钥材料不进入系统，日志与对外响应只出现 `keyId`。
- 信任根与策略由 `GovernanceRegistry` 统一持有。每次写操作互斥，并构造一份全新的不可变
  `GovernanceSnapshot`（带单调递增的 `configVersion`）原子发布。
- **每次准入请求开始时取一次快照，全程只用这一份**：并发地读写配置时，某次请求绝不会
  一半用旧配置、一半用新配置；相同输入在同一快照下结论必然一致。
- 空信任/空策略即**失败关闭**（`POLICY_MISSING`），系统不存在“默认放行”。

## 策略发布期校验

`POST /api/governance/policies` 在策略进入治理状态之前进行校验，失败返回 422，状态不变：

| code | 触发情形 |
|---|---|
| `POLICY_ID_INVALID` | policyId 为空 |
| `POLICY_PATTERN_INVALID` | artifactId / 组件名称正则无法编译 |
| `POLICY_SELF_CONTRADICTION` | 空签名者白名单（禁止一切签名者）；要求证明却禁止所有 builder；要求清单却禁止所有组件 |
| `POLICY_KEY_NOT_TRUSTED` | 策略引用的密钥从未注册（不在信任库） |
| `POLICY_KEY_REVOKED` | 策略引用的密钥已注册但被撤销（REVOKED） |
| `POLICY_KEY_EXPIRED` | 策略引用的密钥已过期（显式 EXPIRED 或发布时刻已超过 notAfter） |
| `POLICY_CONFLICT_AT_PUBLISH` | 与共存策略同优先级且制品范围必然重叠（pattern 相同），运行期将永远冲突 |

密钥引用的发布期拦截口径：**“当前不受信任”= 从未注册、已撤销、已过期**，三种情形分别对应上表
三个可区分的失败码；`RETIRED`（轮换退役）密钥在宽限规则下仍可验证历史签名，引用它的策略允许发布。
拦截不只针对“密钥从没注册过”：注册过、后来被撤销或过期的密钥同样在发布期被挡住。
校验只基于“发布后将生效的新状态”（同 ID 旧策略视为被替换），因此发布要么整体成功，要么整体不发生；
被拦截的发布不留半成品——`configVersion` 不递增、快照与已生效策略完全不变。

## 校验流水线与拒绝原因

按固定顺序判定，任一阶段失败即定终态，原因可区分：

| 顺序 | 检查 | 失败原因 |
|---|---|---|
| 1 | 内容摘要 vs 声明摘要 | `DIGEST_MISMATCH` |
| 2 | 策略选择（缺失/冲突/引用未知密钥） | `POLICY_MISSING` / `POLICY_CONFLICT` / `UNTRUSTED_KEY` |
| 3 | 策略约束（签名者、构建来源） | `SIGNER_NOT_ALLOWED` / `BUILDER_NOT_ALLOWED` |
| 4 | 制品签名（密钥状态 + 验签） | `UNTRUSTED_KEY` / `KEY_REVOKED` / `KEY_EXPIRED` / `SIGNATURE_INVALID` |
| 5 | 来源证明（存在/绑定/签名） | `PROVENANCE_MISSING` / `PROVENANCE_NOT_BOUND` / `PROVENANCE_UNTRUSTED` |
| 6 | 软件成分清单（存在/绑定/组件范围） | `SBOM_MISSING` / `SBOM_NOT_BOUND` / `SBOM_COMPONENT_VIOLATION` |

- 记录状态只有 `PENDING`（批量窗口内短暂存在）、`ADMITTED`、`REJECTED` 三种，不返回无法解释的中间态。
- 清单两类失败严格分开：清单写的制品 `artifactId` 或摘要对不上 → `SBOM_NOT_BOUND`；
  清单确实属于该制品但组件超出策略允许范围 → `SBOM_COMPONENT_VIOLATION`；策略要求但未提供 → `SBOM_MISSING`。
- 即使策略不强制清单，主动提供的清单仍会被校验（绑定 + 组件范围）。

## 结论复核与修订链

- 提交始终按**当前最新快照**重新执行完整校验流水线，从不读取旧结论直接返回。
- **归并（幂等）条件 = 判定依据完全一致**：结论状态、拒绝原因、生效策略来源（`policyId`）、
  签名密钥（`signerKeyId`）四项都相同，才归并为同一条记录。
- 信任或策略变化后，只要判定依据中任何一项变化——哪怕结论状态相同（例如换用更高优先级策略后
  仍然放行）——都会原子追加 `revision+1` 的新记录，**绑定当时的 `configVersion` 与新策略来源**，
  `supersedesRecordId` 指向被取代的旧记录；绝不会把旧记录的策略来源与配置版本直接端回。
- 配置变化若不影响该制品的判定依据（如不匹配该制品的策略、无关密钥注册），结论仍是同一条，
  重复提交保持幂等归并；同一配置下并发/重复提交也只会归并到同一条记录，不会出现互相矛盾的结论。
- 旧记录仍可按 `recordId` 查询，`GET /api/admissions/{recordId}` 永远返回写入时的历史结论，
  历史记录不被改写；按请求哈希则始终解析到**最新**修订。
- 每条判定结论带 `configVersion`，标明它依据的是哪一版信任根+策略。
- 并发边界：在途请求从始至终使用它开始时取到的同一份快照（结论如实绑定该快照版本）；
  撤销/过期完成之后发起的提交，必然读到新快照并直接体现最新信任状态。

### 重放归属

`ReplayGuard` 记录每个 `statementId` 首次归属的请求哈希。同一证明再次出现时：

- 就是原请求本身（含配置变化后的复核）→ 走正常复核；
- 被挪到别的请求/制品上（无论本请求自身判定是放行还是拒绝）→ **直接归回原记录**，
  既不产生新记录，也不凭空放行。该判定按 statementId 加锁，消除并发竞态窗口。

## 策略优先级与失败关闭

1. 策略按 `priority` 数值升序，**小者优先**；取匹配 `artifactIdPattern` 的最高优先级策略。
2. 最高优先级存在多条命中 → `POLICY_CONFLICT`，拒绝（必然冲突的组合在发布期即被拦截）。
3. 无任何策略或无匹配 → `POLICY_MISSING`，拒绝。
4. 策略引用了信任快照中不存在的密钥 → `UNTRUSTED_KEY`，拒绝。
5. 约束列表语义：`null` 不限制；空列表显式禁止一切。

## 密钥轮换、撤销与过期

- **轮换** `rotateKey`：旧密钥转为 `RETIRED` 并记录退役时刻；退役时刻**之前**签发的签名在宽限
  规则下仍有效，之后的一律拒绝（`KEY_EXPIRED`）。
- **撤销** `revokeKey`：该密钥的任何签名立即失效（`KEY_REVOKED`），含历史签名；已放行制品重提会被复核拒绝。
- **过期** `expireKey` 或超过 `notAfter`：一律拒绝（`KEY_EXPIRED`）。
- 所有变更随快照原子发布，并发请求不会看到半更新状态。
- 与发布期校验联动：密钥被撤销或过期后，任何引用它的**新**策略在发布期即被拒
  （`POLICY_KEY_REVOKED` / `POLICY_KEY_EXPIRED`）；此前已生效的策略保留，其请求在运行期
  按最新信任状态失败关闭（`KEY_REVOKED` / `KEY_EXPIRED`）。

## 对外接口

准入：

- `POST /api/admissions` — 提交单个准入请求（可选 `manifest` 字段携带成分清单），返回准入记录。
- `POST /api/admissions/batch` — 批量提交；整批拒绝时返回 422 与原因。
- `GET /api/admissions/{recordId}` — 结论查询（含历史修订）；不存在返回 404。

运行期治理（`/api/governance`，本地模拟未加鉴权；公钥以 X.509 Base64 传入）：

- `GET /snapshot` — 查看当前 configVersion、密钥状态与策略。
- `POST /keys` — 注册/替换受信公钥。
- `POST /keys/rotate` — 轮换密钥（旧密钥 + 新密钥 + retiredAt）。
- `POST /keys/{keyId}/revoke`、`POST /keys/{keyId}/expire` — 撤销 / 置为过期。
- `POST /policies` — 发布（新增或同 ID 替换）策略；校验失败 422。
- `POST /policies/{policyId}/retire` — 下线策略。

## 兼容范围

- 旧的 6 参 `TrustPolicy` 与无 `manifest` 的 `AdmissionRequest` 构造仍然保留，旧调用方无需改动。
- 原有用例（摘要/签名/证明、轮换宽限、失败关闭、幂等、批量、并发一致）全部保留并通过。
- 信任与策略默认空（失败关闭）；可通过治理接口或测试引导（`seedPolicies`）装入配置。

## 本地复现与验证

```bash
mvn -o test              # 离线运行全部测试（46 个用例）
mvn -o spring-boot:run   # 本地启动服务，再用 curl 调 /api/governance 与 /api/admissions
```

测试覆盖（新增部分）：

- 运行期发布/替换/下线策略即时生效、发布期拦截矛盾策略与未知密钥引用、失败发布不改版本；
  并发写治理 + 并发读快照，验证读者只能看到完整一致的快照；
- **发布期密钥信任拦截**：引用已撤销密钥（`POLICY_KEY_REVOKED`）、已过期密钥（显式置过期与
  自然超过 notAfter 两种，`POLICY_KEY_EXPIRED`）的策略在发布期被拒，且配置版本、快照与已生效
  策略均不变；引用 RETIRED（轮换退役）密钥的策略仍允许发布；
- 成分清单缺失、artifactId 不绑定、摘要不绑定、组件越权、可选清单仍受校验；
- 密钥撤销/过期、更高优先级策略发布、策略下线后同一制品重提产生新结论与修订链；
  **判定依据变化（策略来源/签名密钥）即使结论同为放行也起新修订并绑定最新 configVersion**；
  无关配置变更但判定依据不变时归并为同一条记录；旧放行记录绝不被直接端回，历史记录可查不改写；
- **并发撤销/发布/下线 + 并发提交**：同一配置版本下的判定结论确定一致、撤销生效后的判定绝不
  按已撤销密钥放行、撤销完成后的新提交直接体现最新信任状态；
- 同一条证明挪用至别的制品（原样与重签伪造绑定两种）均归回原记录、不产生新记录；
- HTTP 端到端：治理 → 准入（含清单）→ 撤销 → 复核的完整链路。

每个用例日志均打印**输入摘要与判定依据**（`digest=... reason=... configVersion=... basis=...`）
以及各业务的通过情况，见 `target/surefire-reports/`。

手工复现两处修复（服务启动后）：

```bash
# 1) 发布期拦截：注册密钥 → 发布策略 → 撤销 → 再发布引用该密钥的新策略
curl -X POST localhost:8080/api/governance/keys -H 'Content-Type: application/json' \
  -d '{"keyId":"k1","publicKeyBase64":"<X.509 Base64>"}'
curl -X POST localhost:8080/api/governance/policies -H 'Content-Type: application/json' \
  -d '{"policyId":"p1","priority":10,"allowedSignerKeyIds":["k1"]}'
curl -X POST localhost:8080/api/governance/keys/k1/revoke
curl -X POST localhost:8080/api/governance/policies -H 'Content-Type: application/json' \
  -d '{"policyId":"p2","priority":20,"allowedSignerKeyIds":["k1"]}'
#   → 422 {"code":"POLICY_KEY_REVOKED"}；GET /snapshot 可见 configVersion 未变、p2 不存在

# 2) 复核绑定最新配置：放行某制品 → 发布优先级更高且仍放行的新策略 → 相同输入重提
#   → 返回 revision=2 的新记录，policyId 为新策略、configVersion 为最新；
#     GET /api/admissions/{旧recordId} 仍返回历史结论
```
