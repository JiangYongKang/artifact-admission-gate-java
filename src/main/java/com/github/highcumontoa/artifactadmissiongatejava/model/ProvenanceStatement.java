package com.github.highcumontoa.artifactadmissiongatejava.model;

/**
 * 来源证明（本地文件模拟）：声明某构建来源产出了某摘要的制品。
 *
 * @param statementId    证明唯一标识（重放防护以此判重）
 * @param artifactId     制品标识
 * @param artifactDigest 制品 SHA-256 摘要（十六进制小写）
 * @param builderId      构建来源标识
 * @param issuedAtEpochSeconds 签发时间（秒）
 * @param signerKeyId    证明签名密钥标识
 * @param signature      对 statementId|artifactId|artifactDigest|builderId|issuedAt 的签名（Base64）
 */
public record ProvenanceStatement(
        String statementId,
        String artifactId,
        String artifactDigest,
        String builderId,
        long issuedAtEpochSeconds,
        String signerKeyId,
        String signature) {

    /** 被签名的规范化载荷。 */
    public String canonicalPayload() {
        return statementId + "|" + artifactId + "|" + artifactDigest + "|" + builderId + "|" + issuedAtEpochSeconds;
    }
}
