# 离线制品准入校验网关（Artifact Admission Gate）

基于 Spring Boot 3 / Java 21 的**离线**制品准入校验服务。用本地文件模拟制品、签名、来源证明与 SBOM，
对不同信任策略与异常输入给出**一致、可区分、可追溯**的准入结论。详细信任模型见
[`docs/trust-model.md`](docs/trust-model.md)。

## 构建与验证（无需联网、无需真实凭据）

```bash
mvn test          # 编译 + 运行全部单测（运行时生成 RSA 密钥与本地夹具文件）
mvn spring-boot:run   # 启动服务（默认空信任根/空策略，失败关闭）
```

测试覆盖（见 `src/test/.../tests/`，日志会打印输入摘要与判定依据）：

| 测试类 | 覆盖点 |
|--------|--------|
| `HappyPathAdmissionTest` | 完整绑定制品/签名/证明/SBOM 放行；无 SBOM 放行；查询一致性 |
| `NegativeInputTest` | 伪造签名、摘要篡改、证明缺失/畸形/不绑定、伪造证明签名、SBOM 篡改、策略缺失、坏请求 |
| `KeyLifecycleTest` | 轮换前旧签名轮换后仍有效、轮换后签名 `KEY_SUPERSEDED`、撤销对旧签名生效、过期/临期 |
| `PolicyEvaluationTest` | 高优先级 DENY 覆盖低优先级 ALLOW、同优先级冲突发布失败、无匹配默认拒绝、空策略失败关闭 |
| `ReplayProtectionTest` | 重复提交只产生一条记录并计数、重放不能推翻拒绝、撤销后重放由放行翻转为拒绝 |
| `ConcurrencyAdmissionTest` | 32 线程同一证明→1 条记录；40 个不同证明并发不串号 |
| `BatchAdmissionTest` | 超规模整体拒绝、超耗时回滚无残留、空批次、正常批次 |
| `WebApiTest` | 提交/查询契约、终态明确、404、坏 JSON、错误归类 |
| `TrustBootstrapTest` | 目录引导装载、缺目录空信任失败关闭、冲突策略拒绝引导 |
| `SecretMaterialLeakTest` | 响应与审计中不含公钥/签名原文，但含摘要与声明 id |

## HTTP 接口

### 提交准入
`POST /api/admissions`
```json
{
  "artifactPath": "/tmp/artifact.bin",
  "claimedDigest": "可选，填写则会与实算 SHA-256 比对",
  "signaturePath": "/tmp/artifact.sig.json",
  "attestationPath": "/tmp/attestation.json",
  "sbomPath": "/tmp/sbom.json  可空",
  "policyId": "strict-policy"
}
```
成功终态（HTTP 200）：
```json
{
  "admissionId": "uuid", "status": "ADMITTED", "rejectReason": null,
  "artifactDigest": "sha256-hex", "signerKeyId": "key-1",
  "statementId": "stmt-1", "policyId": "strict-policy",
  "replay": false, "replayCount": 0,
  "createdAt": "...", "decidedAt": "...",
  "auditTrail": ["... 判定依据 ..."]
}
```
拒绝终态：`status="REJECTED"`，`rejectReason` 为可区分原因码（见信任模型文档第 2 节）。

### 查询结论
`GET /api/admissions/{admissionId}` → 同上结构；不存在返回 `404 {errorCode:"NOT_FOUND"}`。

### 批量准入
`POST /api/admissions/batch`，请求体 `{"items":[ <AdmissionRequest>... ]}`。
超规模/超耗时返回 `accepted=false` 与 `BATCH_TOO_LARGE`/`BATCH_TIMEOUT`，且不留部分状态。

### 管理接口（仅本地模拟，密钥材料永不回显）
- `POST /api/admin/keys`：注册信任根（body 给 `publicKeyPemPath`，不是材料内联）
- `POST /api/admin/keys/{keyId}/revoke`：撤销
- `POST /api/admin/keys/{oldKeyId}/rotate`：轮换（body 为新根注册信息）
- `GET  /api/admin/keys`：仅列出 keyId/状态/时间点
- `POST /api/admin/policies` / `GET /api/admin/policies`：配置 / 列出策略

## 失败关闭（fail-closed）原则速览

未知密钥、撤销/过期/被轮换后签发、策略缺失/冲突/无匹配、证明缺失或不绑定、摘要不符、
验签失败、SBOM 不绑定、批量超限/超时——**一律拒绝或整体失败，绝不默认放行**。
