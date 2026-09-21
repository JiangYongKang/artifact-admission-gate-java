package com.github.highcumontoa.artifactadmissiongatejava.api;

import com.github.highcumontoa.artifactadmissiongatejava.domain.KeyState;

import java.time.Instant;

/** 信任根注册/轮换/撤销请求。keyMaterial 仅在注册时通过本地文件路径或 PEM 文本传入，永不回显。 */
public record RegisterKeyRequest(
        String keyId,
        String publicKeyPemPath,
        KeyState state,
        Instant expiresAt,
        Instant rotatedAt,
        String replacedKeyId
) {
}
