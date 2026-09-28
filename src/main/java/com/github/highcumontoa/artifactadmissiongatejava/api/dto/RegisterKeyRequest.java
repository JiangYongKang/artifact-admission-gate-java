package com.github.highcumontoa.artifactadmissiongatejava.api.dto;

import java.time.Instant;

/**
 * 注册受信密钥请求：只接受公钥材料（X.509 SubjectPublicKeyInfo 的 Base64 编码）。
 *
 * @param keyId            密钥标识
 * @param publicKeyBase64  X.509 编码公钥（Base64）
 * @param notBefore        生效时间，可空
 * @param notAfter         失效时间，可空
 */
public record RegisterKeyRequest(String keyId, String publicKeyBase64, Instant notBefore, Instant notAfter) {
}
