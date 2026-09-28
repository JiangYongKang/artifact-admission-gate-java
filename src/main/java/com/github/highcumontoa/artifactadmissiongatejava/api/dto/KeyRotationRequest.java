package com.github.highcumontoa.artifactadmissiongatejava.api.dto;

/** 运行期轮换密钥请求：旧密钥退役时刻 + 新密钥公钥。 */
public record KeyRotationRequest(
        String oldKeyId,
        String newKeyId,
        String newPublicKeyBase64,
        String retiredAt) {
}
