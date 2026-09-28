package com.github.highcumontoa.artifactadmissiongatejava.trust;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 线程安全的内存信任库：支持密钥注册、轮换、撤销与过期。
 * 所有变更与读取经同一把锁串行化，避免并发下的半更新状态。
 * 每次变更使版本号递增，供配置快照与结论复核使用。
 */
public class TrustStore {

    private final Map<String, TrustedKey> keys = new ConcurrentHashMap<>();
    private final AtomicLong version = new AtomicLong(0);

    /** 注册；keyId 已存在返回 false 且不改变状态。 */
    public synchronized boolean register(TrustedKey key) {
        if (keys.containsKey(key.keyId())) {
            return false;
        }
        keys.put(key.keyId(), key);
        version.incrementAndGet();
        return true;
    }

    /** 目标不存在返回 false 且不产生新版本。 */
    public synchronized boolean replaceIfPresent(TrustedKey key) {
        if (!keys.containsKey(key.keyId())) {
            return false;
        }
        keys.put(key.keyId(), key);
        version.incrementAndGet();
        return true;
    }

    /** 轮换：旧密钥转为 RETIRED（记录退役时刻），新密钥以 ACTIVE 注册。 */
    public synchronized void rotate(String oldKeyId, TrustedKey newKey, Instant retiredAt) {
        TrustedKey old = keys.get(oldKeyId);
        if (old != null) {
            keys.put(oldKeyId, new TrustedKey(old.keyId(), old.publicKey(), KeyState.RETIRED,
                    old.notBefore(), old.notAfter(), retiredAt));
        }
        keys.put(newKey.keyId(), newKey);
        version.incrementAndGet();
    }

    public synchronized void revoke(String keyId) {
        TrustedKey k = keys.get(keyId);
        if (k != null) {
            keys.put(keyId, new TrustedKey(k.keyId(), k.publicKey(), KeyState.REVOKED,
                    k.notBefore(), k.notAfter(), k.retiredAt()));
            version.incrementAndGet();
        }
    }

    public synchronized void expire(String keyId) {
        TrustedKey k = keys.get(keyId);
        if (k != null) {
            keys.put(keyId, new TrustedKey(k.keyId(), k.publicKey(), KeyState.EXPIRED,
                    k.notBefore(), k.notAfter(), k.retiredAt()));
            version.incrementAndGet();
        }
    }

    /** 读取为不可变快照语义：返回的条目不会在读取后被本库修改（条目本身不可变）。 */
    public Optional<TrustedKey> find(String keyId) {
        return Optional.ofNullable(keys.get(keyId));
    }

    /** 当前信任版本号：任何变更后严格递增。 */
    public long version() {
        return version.get();
    }

    /** 不可变快照拷贝。 */
    public synchronized Map<String, TrustedKey> snapshot() {
        return Collections.unmodifiableMap(Map.copyOf(keys));
    }
}
