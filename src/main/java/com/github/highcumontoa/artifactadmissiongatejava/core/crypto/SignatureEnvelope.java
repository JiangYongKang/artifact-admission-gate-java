package com.github.highcumontoa.artifactadmissiongatejava.core.crypto;

import java.time.Instant;

/**
 * 签名信封（本地 JSON 文件模拟）：对某个摘要的签名。
 * 制品签名与来源证明签名共用此信封格式。
 */
public record SignatureEnvelope(
        String keyId,
        String signedDigest,
        String algorithm,
        Instant signedAt,
        String signatureBase64
) {
}
