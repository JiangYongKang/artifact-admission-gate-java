package com.github.highcumontoa.artifactadmissiongatejava.api.dto;

/**
 * 运行期注册密钥请求（仅公钥，Base64 的 X.509 SubjectPublicKeyInfo；本地模拟，不接真实凭据）。
 */
public record KeyEnrollmentRequest(
        String keyId,
        String publicKeyBase64,
        String notBefore,
        String notAfter) {
}
