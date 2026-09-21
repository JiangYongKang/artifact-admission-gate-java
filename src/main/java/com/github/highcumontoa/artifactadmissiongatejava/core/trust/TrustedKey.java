package com.github.highcumontoa.artifactadmissiongatejava.core.trust;

import com.github.highcumontoa.artifactadmissiongatejava.domain.KeyState;

import java.security.PublicKey;
import java.time.Instant;

/**
 * 信任根公钥条目。公钥材料仅存在内存中，禁止日志/序列化输出。
 */
public final class TrustedKey {

    private final String keyId;
    private final PublicKey publicKey;
    private final KeyState state;
    private final Instant expiresAt;
    private final Instant rotatedAt;
    private final String replacedKeyId;

    public TrustedKey(String keyId, PublicKey publicKey, KeyState state,
                      Instant expiresAt, Instant rotatedAt, String replacedKeyId) {
        this.keyId = keyId;
        this.publicKey = publicKey;
        this.state = state;
        this.expiresAt = expiresAt;
        this.rotatedAt = rotatedAt;
        this.replacedKeyId = replacedKeyId;
    }

    public String getKeyId() { return keyId; }
    public PublicKey getPublicKey() { return publicKey; }
    public KeyState getState() { return state; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getRotatedAt() { return rotatedAt; }
    public String getReplacedKeyId() { return replacedKeyId; }

    /** 绝不能在日志/响应中暴露密钥材料。 */
    @Override
    public String toString() {
        return "TrustedKey{keyId=" + keyId + ",state=" + state + "}";
    }
}
