# Artifact Admission Gate（离线制品准入校验）

以本地文件模拟制品、签名、来源证明（Provenance）与软件成分声明，对制品执行
**摘要 + 签名 + 来源证明** 的联合校验，在任意信任策略与异常输入下给出
一致、可区分、可追溯的准入结论。全程仅依赖 JDK 与 Spring Boot，不访问任何外部服务。

## 信任模型

```
制品内容(Base64) ──SHA-256──> 计算摘要 ──比对──> 声明摘要
声明摘要 ──Ed25519 验签(签名者公钥)──> 签名有效性
来源证明(ProvenanceStatement) ──绑定(artifactId+摘要)──> 制品
来源证明 ──Ed25519 验签(证明者公钥)──> 证明可信性
信任库(TrustStore) ──密钥状态: ACTIVE / RETIRED / REVOKED / EXPIRED
策略引擎(PolicyEngine) ──签名者/构建来源/制品标识约束，按优先级组合
```

- 密钥仅持有**公钥**；私钥材料不进入系统，日志与对外响应只出现 `keyId`。
- 证明按 `statementId` 消费（ReplayGuard）：同一证明重复提交不会产生新记录，
  也无法绕过已生效的撤销/拒绝结论；同一请求的重复提交按请求哈希幂等返回原记录。

## 校验流水线与拒绝原因

按固定顺序判定，任一阶段失败即定终态，原因可区分：

| 顺序 | 检查 | 失败原因 |
|---|---|---|
| 1 | 内容摘要 vs 声明摘要 | `DIGEST_MISMATCH` |
| 2 | 策略选择（缺失/冲突/引用未知密钥） | `POLICY_MISSING` / `POLICY_CONFLICT` / `UNTRUSTED_KEY` |
| 3 | 策略约束（签名者、构建来源） | `SIGNER_NOT_ALLOWED` / `BUILDER_NOT_ALLOWED` |
| 4 | 制品签名（密钥状态 + 验签） | `UNTRUSTED_KEY` / `KEY_REVOKED` / `KEY_EXPIRED` / `SIGNATURE_INVALID` |
| 5 | 来源证明（存在/绑定/签名/重放） | `PROVENANCE_MISSING` / `PROVENANCE_NOT_BOUND` / `PROVENANCE_UNTRUSTED` / `PROVENANCE_REPLAYED` |

记录状态只有 `PENDING`（批量窗口内短暂存在）、`ADMITTED`、`REJECTED` 三种，
任何请求都不会返回无法解释的中间态；结论一旦写入即不可变。

## 策略优先级与失败关闭

1. 策略按 `priority` 数值升序，**小者优先**；取匹配 `artifactIdPattern` 的最高优先级策略。
2. 最高优先级存在多条命中 → `POLICY_CONFLICT`，拒绝。
3. 无任何策略或无匹配 → `POLICY_MISSING`，拒绝。
4. 策略引用了信任库中不存在的密钥 → `UNTRUSTED_KEY`，拒绝。
5. 约束字段语义：`null` 不限制；空列表显式禁止一切。

**失败关闭（fail-closed）**：以上任何不确定情形一律拒绝，绝不默认放行。

## 密钥轮换、撤销与过期

- **轮换** `TrustStore.rotate`：旧密钥转为 `RETIRED` 并记录退役时刻；
  退役时刻**之前**签发的签名在宽限规则下仍有效，之后的一律拒绝（`KEY_EXPIRED`）。
- **撤销** `revoke`：该密钥的任何签名立即失效（`KEY_REVOKED`），含历史签名。
- **过期** `expire` 或超过 `notAfter`：一律拒绝（`KEY_EXPIRED`）。
- 信任库所有变更与读取经同一把锁串行化，条目不可变，无半更新状态。

## 并发与批量

- 所有组件（Store / TrustStore / PolicyEngine / ReplayGuard）线程安全；
  同一请求并发提交解析为**同一条记录**（先写记录再发布索引，读者不会拿到缺失记录）。
- 批量上限：`admission.batch.max-size`（默认 100）与 `admission.batch.max-duration-ms`（默认 5000）。
  规模超限**整批拒绝**且不落任何记录；耗时超限则剩余项以 `BATCH_LIMIT_EXCEEDED`
  明确拒绝，每条记录均为完整终态，无部分状态残留。

## 对外接口

- `POST /api/admissions` — 提交单个准入请求，返回准入记录（含状态、原因、判定依据）。
- `POST /api/admissions/batch` — 批量提交；整批拒绝时返回 422 与原因。
- `GET /api/admissions/{recordId}` — 结论查询；不存在返回 404。

## 本地复现与验证

```bash
mvn -o test        # 离线运行全部测试（19 个用例）
mvn -o spring-boot:run   # 本地启动服务
```

测试覆盖：伪造签名、摘要篡改、证明与制品不绑定、证明签名伪造、密钥轮换/撤销/过期、
策略冲突/缺失/引用未知密钥、签名者越权、重复提交幂等、证明重放、并发准入一致性、
批量规模与耗时上限。每个用例日志均打印**输入摘要与判定依据**
（`inputDigest=... basis=...`），见 `target/surefire-reports/`。
