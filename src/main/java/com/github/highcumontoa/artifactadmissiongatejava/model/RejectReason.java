package com.github.highcumontoa.artifactadmissiongatejava.model;

/** 拒绝原因分类：每类原因必须可区分、可解释。 */
public enum RejectReason {
    /** 提交摘要与制品实际摘要不一致。 */
    DIGEST_MISMATCH,
    /** 制品签名无法被所声明密钥验证。 */
    SIGNATURE_INVALID,
    /** 缺少来源证明。 */
    PROVENANCE_MISSING,
    /** 来源证明未绑定到该制品（摘要/标识不符）。 */
    PROVENANCE_NOT_BOUND,
    /** 来源证明签名无效或证明者不被信任。 */
    PROVENANCE_UNTRUSTED,
    /** 证明被重放（同一证明已产生过结论）。 */
    PROVENANCE_REPLAYED,
    /** 策略在发布阶段即非法（自相矛盾或不可解析），失败关闭。 */
    POLICY_INVALID,
    /** 策略要求软件成分清单但未提供。 */
    SBOM_MISSING,
    /** 软件成分清单未绑定到该制品（标识/摘要与实际制品不符）。 */
    SBOM_NOT_BOUND,
    /** 软件成分清单签名无效或签名者不被信任。 */
    SBOM_UNTRUSTED,
    /** 清单中的组件超出策略允许范围。 */
    SBOM_COMPONENT_NOT_ALLOWED,
    /** 未配置任何适用策略，失败关闭。 */
    POLICY_MISSING,
    /** 策略约束互相冲突，无法安全判定，失败关闭。 */
    POLICY_CONFLICT,
    /** 策略引用了信任库中不存在或不可用的密钥。 */
    UNTRUSTED_KEY,
    /** 签名密钥已被撤销。 */
    KEY_REVOKED,
    /** 签名密钥已过期（含轮换后旧签名超宽限）。 */
    KEY_EXPIRED,
    /** 签名者不在策略允许列表。 */
    SIGNER_NOT_ALLOWED,
    /** 构建来源不在策略允许列表。 */
    BUILDER_NOT_ALLOWED,
    /** 制品标识不匹配策略约束。 */
    ARTIFACT_NOT_ALLOWED,
    /** 批量请求超过规模或耗时上限。 */
    BATCH_LIMIT_EXCEEDED
}
