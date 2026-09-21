package com.github.highcumontoa.artifactadmissiongatejava.trust;

import java.security.PublicKey;
import java.time.Instant;

/**
 * 信任库中的密钥条目。私钥材料绝不进入本对象，日志与响应中只允许出现 keyId。
 *
 * @param keyId        密钥标识
 * @param publicKey    公钥（Ed25519）
 * @param state        生命周期状态
 * @param notBefore    生效时间
 * @param notAfter     失效时间（超过即视为过期）
 * @param retiredAt    轮换退役时间；RETIRED 时有效，此前签发的签名仍可按宽限规则验证
 */
public record TrustedKey(
        String keyId,
        PublicKey publicKey,
        KeyState state,
        Instant notBefore,
        Instant notAfter,
        Instant retiredAt) {

    public boolean isRevoked() {
        return state == KeyState.REVOKED;
    }

    /** 在指定判定时刻是否已过期（显式 EXPIRED 或超过 notAfter）。 */
    public boolean isExpiredAt(Instant when) {
        return state == KeyState.EXPIRED || (notAfter != null && when.isAfter(notAfter));
    }

    /**
     * 轮换宽限规则：RETIRED 密钥仅允许验证签发时间早于 retiredAt 的签名。
     */
    public boolean usableForSignatureIssuedAt(Instant issuedAt, Instant now) {
        return switch (state) {
            case ACTIVE -> !isExpiredAt(now) && (notBefore == null || !issuedAt.isBefore(notBefore));
            case RETIRED -> retiredAt != null && issuedAt.isBefore(retiredAt) && !isExpiredAt(now);
            case REVOKED, EXPIRED -> false;
        };
    }

    /** 日志安全的形式：绝不输出密钥材料。 */
    @Override
    public String toString() {
        return "TrustedKey{keyId=" + keyId + ", state=" + state + "}";
    }
}
