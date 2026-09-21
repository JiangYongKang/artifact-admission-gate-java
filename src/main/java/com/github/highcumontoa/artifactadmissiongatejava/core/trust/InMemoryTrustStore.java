package com.github.highcumontoa.artifactadmissiongatejava.core.trust;

import com.github.highcumontoa.artifactadmissiongatejava.domain.KeyState;
import com.github.highcumontoa.artifactadmissiongatejava.domain.RejectReason;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 内存信任根库。
 *
 * 信任模型与既定规则：
 * - 未登记的密钥：KEY_UNTRUSTED（引用不可信密钥失败关闭）。
 * - REVOKED：一律拒绝 KEY_REVOKED，撤销对历史签名同样生效（撤销不豁免旧签名）。
 * - 已过期（expiresAt &lt;= now）：KEY_EXPIRED。
 * - ROTATED：仅当签名时间严格早于轮换时间（signedAt &lt; rotatedAt）时旧签名仍有效，
 *   轮换之后产生的签名拒绝 KEY_SUPERSEDED。
 * - ACTIVE：正常有效。
 */
@Component
public class InMemoryTrustStore implements TrustStore {

    private final Map<String, TrustedKey> keys = new ConcurrentHashMap<>();

    @Override
    public void register(TrustedKey key) {
        if (key == null || key.getKeyId() == null || key.getKeyId().isBlank()) {
            throw new IllegalArgumentException("key-id-required");
        }
        keys.put(key.getKeyId(), key);
    }

    @Override
    public synchronized void rotate(String oldKeyId, String newKeyId, Instant rotatedAt) {
        TrustedKey oldKey = require(oldKeyId);
        TrustedKey newKey = require(newKeyId);
        if (newKey.getState() != KeyState.ACTIVE) {
            throw new IllegalStateException("rotation-target-must-be-active:" + newKeyId);
        }
        Instant at = rotatedAt != null ? rotatedAt : Instant.now();
        // 旧根置为 ROTATED 并记录被哪个根替代；新根保持 ACTIVE。整体在同一把锁内完成，避免半更新。
        keys.put(oldKeyId, new TrustedKey(oldKey.getKeyId(), oldKey.getPublicKey(), KeyState.ROTATED,
                oldKey.getExpiresAt(), at, newKeyId));
    }

    @Override
    public synchronized void revoke(String keyId, Instant at) {
        TrustedKey key = require(keyId);
        keys.put(keyId, new TrustedKey(key.getKeyId(), key.getPublicKey(), KeyState.REVOKED,
                key.getExpiresAt(), key.getRotatedAt(), key.getReplacedKeyId()));
    }

    @Override
    public TrustedKey get(String keyId) {
        return keys.get(keyId);
    }

    @Override
    public TrustVerdict assess(String keyId, Instant signedAt, Instant now) {
        TrustedKey key = keys.get(keyId);
        if (key == null) {
            return new TrustVerdict(false, RejectReason.KEY_UNTRUSTED, keyId);
        }
        if (key.getState() == KeyState.REVOKED) {
            return new TrustVerdict(false, RejectReason.KEY_REVOKED, keyId);
        }
        if (key.getExpiresAt() != null && !now.isBefore(key.getExpiresAt())) {
            return new TrustVerdict(false, RejectReason.KEY_EXPIRED, keyId);
        }
        if (key.getState() == KeyState.ROTATED) {
            Instant rotatedAt = key.getRotatedAt() != null ? key.getRotatedAt() : now;
            if (signedAt == null || !signedAt.isBefore(rotatedAt)) {
                return new TrustVerdict(false, RejectReason.KEY_SUPERSEDED, keyId);
            }
        }
        return TrustVerdict.ok(keyId);
    }

    @Override
    public List<String> keyIds() {
        return new ArrayList<>(keys.keySet());
    }

    private TrustedKey require(String keyId) {
        TrustedKey key = keys.get(keyId);
        if (key == null) {
            throw new NoSuchElementException("unknown-key:" + keyId);
        }
        return key;
    }
}
