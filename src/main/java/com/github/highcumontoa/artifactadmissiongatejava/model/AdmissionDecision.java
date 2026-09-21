package com.github.highcumontoa.artifactadmissiongatejava.model;

import java.time.Instant;

/**
 * 一次校验的判定结论（不可变）。
 *
 * @param status          结论状态
 * @param reason          拒绝原因；放行时为 null
 * @param detail          人类可读的判定依据（不含密钥材料）
 * @param computedDigest  实际计算的制品摘要
 * @param policyId        生效策略标识
 * @param signerKeyId     涉及的签名密钥标识
 * @param decidedAt       判定时间
 */
public record AdmissionDecision(
        AdmissionStatus status,
        RejectReason reason,
        String detail,
        String computedDigest,
        String policyId,
        String signerKeyId,
        Instant decidedAt) {

    public static AdmissionDecision admitted(String detail, String digest, String policyId, String keyId) {
        return new AdmissionDecision(AdmissionStatus.ADMITTED, null, detail, digest, policyId, keyId, Instant.now());
    }

    public static AdmissionDecision rejected(RejectReason reason, String detail, String digest, String policyId, String keyId) {
        return new AdmissionDecision(AdmissionStatus.REJECTED, reason, detail, digest, policyId, keyId, Instant.now());
    }
}
