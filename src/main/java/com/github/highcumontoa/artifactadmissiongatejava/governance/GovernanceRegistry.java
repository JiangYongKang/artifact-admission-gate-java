package com.github.highcumontoa.artifactadmissiongatejava.governance;

import com.github.highcumontoa.artifactadmissiongatejava.policy.TrustPolicy;
import com.github.highcumontoa.artifactadmissiongatejava.trust.KeyState;
import com.github.highcumontoa.artifactadmissiongatejava.trust.TrustedKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 运行期治理注册表：密钥与策略均可在运行中管理，无需重启。
 *
 * 所有写操作互斥，每次变更都构造一份全新的不可变 {@link GovernanceSnapshot} 并原子发布；
 * 请求侧拿到快照引用后全程只读，因此读操作天然无锁且绝不会看到半更新状态。
 * 策略发布先在待发布的新状态上做校验，校验失败则放弃发布，治理状态保持不变。
 */
public class GovernanceRegistry {

    private static final Logger log = LoggerFactory.getLogger(GovernanceRegistry.class);

    private final Map<String, TrustedKey> keys = new LinkedHashMap<>();
    private final Map<String, TrustPolicy> policiesById = new LinkedHashMap<>();
    private final AtomicLong versionSeq = new AtomicLong(0);
    private final Clock clock;
    private volatile GovernanceSnapshot current = new GovernanceSnapshot(0, Map.of(), List.of());

    public GovernanceRegistry() {
        this(Clock.systemUTC());
    }

    public GovernanceRegistry(Clock clock) {
        this.clock = clock;
    }

    public GovernanceSnapshot current() {
        return current;
    }

    // ---------------- 密钥治理 ----------------

    /** 新增或替换注册一把受信密钥。 */
    public synchronized void registerKey(TrustedKey key) {
        keys.put(key.keyId(), key);
        publish("key registered: " + key.keyId());
    }

    /** 轮换：旧密钥转为 RETIRED（记录退役时刻），新密钥以 ACTIVE 注册，原子生效。 */
    public synchronized void rotateKey(String oldKeyId, TrustedKey newKey, Instant retiredAt) {
        TrustedKey old = keys.get(oldKeyId);
        if (old != null) {
            keys.put(oldKeyId, new TrustedKey(old.keyId(), old.publicKey(), KeyState.RETIRED,
                    old.notBefore(), old.notAfter(), retiredAt));
        }
        keys.put(newKey.keyId(), newKey);
        publish("key rotated: " + oldKeyId + " -> " + newKey.keyId() + ", retiredAt=" + retiredAt);
    }

    /** 撤销：该密钥的任何签名立即失效（含历史签名）。 */
    public synchronized void revokeKey(String keyId) {
        TrustedKey k = keys.get(keyId);
        if (k == null) {
            throw new IllegalArgumentException("unknown key: " + keyId);
        }
        keys.put(keyId, new TrustedKey(k.keyId(), k.publicKey(), KeyState.REVOKED,
                k.notBefore(), k.notAfter(), k.retiredAt()));
        publish("key revoked: " + keyId);
    }

    /** 显式置为过期。 */
    public synchronized void expireKey(String keyId) {
        TrustedKey k = keys.get(keyId);
        if (k == null) {
            throw new IllegalArgumentException("unknown key: " + keyId);
        }
        keys.put(keyId, new TrustedKey(k.keyId(), k.publicKey(), KeyState.EXPIRED,
                k.notBefore(), k.notAfter(), k.retiredAt()));
        publish("key expired: " + keyId);
    }

    public Optional<TrustedKey> findKey(String keyId) {
        return current.findKey(keyId);
    }

    // ---------------- 策略治理 ----------------

    /**
     * 发布（新增或同 ID 替换）一份策略。
     * 自相矛盾、非法正则或引用当前不受信任（未注册/已撤销/已过期）密钥时
     * 抛出 {@link PolicyPublicationException}，状态与配置版本保持不变。
     */
    public synchronized void publishPolicy(TrustPolicy policy) {
        List<TrustPolicy> others = new ArrayList<>();
        for (TrustPolicy existing : policiesById.values()) {
            if (!existing.policyId().equals(policy.policyId())) {
                others.add(existing);
            }
        }
        PolicyGovernance.validate(policy, others, id -> Optional.ofNullable(keys.get(id)), clock.instant());
        policiesById.put(policy.policyId(), policy);
        publish("policy published: " + policy.policyId() + " priority=" + policy.priority());
    }

    /** 下线（删除）一份策略；不存在时抛出。 */
    public synchronized void retirePolicy(String policyId) {
        if (policiesById.remove(policyId) == null) {
            throw new IllegalArgumentException("unknown policy: " + policyId);
        }
        publish("policy retired: " + policyId);
    }

    /**
     * 测试/引导用：整体替换策略集，跳过发布期逐份校验（用于构造“发布期不可能存在”的运行期形态，
     * 例如同优先级冲突）。仍会发布新版本快照。
     */
    public synchronized void seedPolicies(List<TrustPolicy> newPolicies) {
        policiesById.clear();
        for (TrustPolicy p : newPolicies) {
            policiesById.put(p.policyId(), p);
        }
        publish("policy set replaced (seed), count=" + newPolicies.size());
    }

    // ---------------- 快照发布 ----------------

    private void publish(String change) {
        long version = versionSeq.incrementAndGet();
        current = new GovernanceSnapshot(version, Map.copyOf(keys), List.copyOf(policiesById.values()));
        log.info("governance changed: {} -> configVersion={}", change, version);
    }
}
