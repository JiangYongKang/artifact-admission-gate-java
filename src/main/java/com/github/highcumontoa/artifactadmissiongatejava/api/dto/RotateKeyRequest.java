package com.github.highcumontoa.artifactadmissiongatejava.api.dto;

import java.time.Instant;

/**
 * 密钥轮换请求：旧密钥在 retiredAt 之后签发的签名不再有效（宽限规则）。
 */
public record RotateKeyRequest(String oldKeyId, String newKeyId, String newPublicKeyBase64, Instant retiredAt) {
}
