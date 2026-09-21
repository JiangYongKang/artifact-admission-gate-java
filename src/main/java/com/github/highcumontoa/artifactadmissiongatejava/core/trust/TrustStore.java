package com.github.highcumontoa.artifactadmissiongatejava.core.trust;

import com.github.highcumontoa.artifactadmissiongatejava.domain.KeyState;

import java.security.PublicKey;
import java.time.Instant;
import java.util.List;

/**
 * 信任根库：注册、轮换、撤销、过期判定。所有读写线程安全。
 */
public interface TrustStore {

    void register(TrustedKey key);

    void rotate(String oldKeyId, String newKeyId, Instant rotatedAt);

    void revoke(String keyId, Instant at);

    TrustedKey get(String keyId);

    /** 按签名时间判定某密钥此刻是否可用于验签；失败关闭并给出可区分原因。 */
    TrustVerdict assess(String keyId, Instant signedAt, Instant now);

    List<String> keyIds();
}
