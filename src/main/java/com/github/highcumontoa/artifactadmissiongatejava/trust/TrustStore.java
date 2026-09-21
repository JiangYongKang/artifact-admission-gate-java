package com.github.highcumontoa.artifactadmissiongatejava.trust;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 线程安全的内存信任库：支持密钥注册、轮换、撤销与过期。
 * 所有变更与读取经同一把锁串行化，避免并发下的半更新状态。
 */
public class TrustStore {

    private final Map<String, TrustedKey> keys = new ConcurrentHashMap<>();

    public synchronized void register(TrustedKey key) {
        keys.put(key.keyId(), key);
    }

    /** 轮换：旧密钥转为 RETIRED（记录退役时刻），新密钥以 ACTIVE 注册。 */
    public synchronized void rotate(String oldKeyId, TrustedKey newKey, Instant retiredAt) {
        TrustedKey old = keys.get(oldKeyId);
        if (old != null) {
            keys.put(oldKeyId, new TrustedKey(old.keyId(), old.publicKey(), KeyState.RETIRED,
                    old.notBefore(), old.notAfter(), retiredAt));
        }
        keys.put(newKey.keyId(), newKey);
    }

    public synchronized void revoke(String keyId) {
        TrustedKey k = keys.get(keyId);
        if (k != null) {
            keys.put(keyId, new TrustedKey(k.keyId(), k.publicKey(), KeyState.REVOKED,
                    k.notBefore(), k.notAfter(), k.retiredAt()));
        }
    }

    public synchronized void expire(String keyId) {
        TrustedKey k = keys.get(keyId);
        if (k != null) {
            keys.put(keyId, new TrustedKey(k.keyId(), k.publicKey(), KeyState.EXPIRED,
                    k.notBefore(), k.notAfter(), k.retiredAt()));
        }
    }

    /** 读取为不可变快照语义：返回的条目不会在读取后被本库修改（条目本身不可变）。 */
    public Optional<TrustedKey> find(String keyId) {
        return Optional.ofNullable(keys.get(keyId));
    }
}
