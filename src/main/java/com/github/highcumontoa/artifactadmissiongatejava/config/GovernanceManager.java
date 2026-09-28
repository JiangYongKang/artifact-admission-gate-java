package com.github.highcumontoa.artifactadmissiongatejava.config;

import com.github.highcumontoa.artifactadmissiongatejava.policy.PolicyEngine;
import com.github.highcumontoa.artifactadmissiongatejava.policy.TrustPolicy;
import com.github.highcumontoa.artifactadmissiongatejava.trust.TrustStore;
import com.github.highcumontoa.artifactadmissiongatejava.trust.TrustedKey;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.PatternSyntaxException;

/**
 * 运行期配置治理：集中管理信任根与策略，支持密钥新增/轮换/撤销/过期，
 * 策略发布/替换/下线；所有变更经同一把锁串行化并原子发布为新版本快照。
 *
 * <p>发布阶段即校验策略（正则可编译、ID 不重复、同优先级不重叠、引用的密钥当前受信任），
 * 非法配置一律以 {@link GovernanceException} 拒绝，绝不进入生效集合——非法配置不会
 * 被拖到有请求进来时才暴露。每次成功变更使配置版本严格递增，之后进来的请求立刻看到新版本。
 */
public class GovernanceManager implements ConfigurationRegistry {

    private final TrustStore trustStore;
    private final PolicyEngine policyEngine;
    private final AtomicLong configVersion = new AtomicLong(0);
    private volatile ConfigurationSnapshot published;

    public GovernanceManager(TrustStore trustStore, PolicyEngine policyEngine) {
        this.trustStore = trustStore;
        this.policyEngine = policyEngine;
        this.published = snapshotLocked();
    }

    @Override
    public ConfigurationSnapshot currentSnapshot() {
        // 变更在锁内重发布快照；读取 volatile 引用即获得原子可见的整版配置。
        return published;
    }

    /** 新增密钥；keyId 已存在则拒绝。 */
    public void registerKey(TrustedKey key) {
        if (key == null || key.keyId() == null) {
            throw new GovernanceException(GovernanceException.Kind.KEY_CONFLICT, "key and keyId required");
        }
        synchronized (this) {
            if (!trustStore.register(key)) {
                throw new GovernanceException(GovernanceException.Kind.KEY_CONFLICT,
                        "key already registered: " + key.keyId());
            }
            republish();
        }
    }

    /** 轮换密钥：旧密钥退役（记录退役时刻），新密钥生效，原子发布新版本。 */
    public void rotateKey(String oldKeyId, TrustedKey newKey, Instant retiredAt) {
        if (newKey == null || newKey.keyId() == null) {
            throw new GovernanceException(GovernanceException.Kind.KEY_CONFLICT, "new key required");
        }
        synchronized (this) {
            if (trustStore.find(oldKeyId).isEmpty()) {
                throw new GovernanceException(GovernanceException.Kind.KEY_CONFLICT,
                        "cannot rotate unknown key: " + oldKeyId);
            }
            trustStore.rotate(oldKeyId, newKey, retiredAt);
            republish();
        }
    }

    /** 撤销密钥：立即失效（含历史签名）。 */
    public void revokeKey(String keyId) {
        synchronized (this) {
            if (trustStore.find(keyId).isEmpty()) {
                throw new GovernanceException(GovernanceException.Kind.KEY_CONFLICT,
                        "cannot revoke unknown key: " + keyId);
            }
            trustStore.revoke(keyId);
            republish();
        }
    }

    /** 置为过期：立即失效。 */
    public void expireKey(String keyId) {
        synchronized (this) {
            if (trustStore.find(keyId).isEmpty()) {
                throw new GovernanceException(GovernanceException.Kind.KEY_CONFLICT,
                        "cannot expire unknown key: " + keyId);
            }
            trustStore.expire(keyId);
            republish();
        }
    }

    /** 发布（新增）策略；ID 重复、策略矛盾或引用不受信任密钥则在发布阶段拒绝。 */
    public void publishPolicy(TrustPolicy policy) {
        validateShape(policy);
        synchronized (this) {
            if (policyEngine.snapshot().stream().anyMatch(p -> p.policyId().equals(policy.policyId()))) {
                throw new GovernanceException(GovernanceException.Kind.POLICY_CONFLICT,
                        "policy id already published: " + policy.policyId());
            }
            validateAgainst(policy, policyEngine.snapshot(), trustStore.snapshot());
            if (!policyEngine.add(policy)) {
                throw new GovernanceException(GovernanceException.Kind.POLICY_CONFLICT,
                        "policy id already published: " + policy.policyId());
            }
            republish();
        }
    }

    /** 替换策略（不存在则拒绝）；替换内容同样经过发布校验（按替换后的集合校验冲突）。 */
    public void replacePolicy(TrustPolicy policy) {
        validateShape(policy);
        synchronized (this) {
            List<TrustPolicy> current = policyEngine.snapshot();
            if (current.stream().noneMatch(p -> p.policyId().equals(policy.policyId()))) {
                throw new GovernanceException(GovernanceException.Kind.POLICY_CONFLICT,
                        "no such policy to replace: " + policy.policyId());
            }
            List<TrustPolicy> others = current.stream()
                    .filter(p -> !p.policyId().equals(policy.policyId())).toList();
            validateAgainst(policy, others, trustStore.snapshot());
            if (!policyEngine.replace(policy)) {
                throw new GovernanceException(GovernanceException.Kind.POLICY_CONFLICT,
                        "no such policy to replace: " + policy.policyId());
            }
            republish();
        }
    }

    /** 下线（删除）策略；不存在则拒绝。下线后命中不到策略的请求将失败关闭。 */
    public void retirePolicy(String policyId) {
        synchronized (this) {
            if (!policyEngine.remove(policyId)) {
                throw new GovernanceException(GovernanceException.Kind.POLICY_CONFLICT,
                        "no such policy to retire: " + policyId);
            }
            republish();
        }
    }

    // ---- 发布阶段校验：非法配置绝不进入生效集合 ----

    /** 形状校验：正则可编译。 */
    static void validateShape(TrustPolicy policy) {
        if (policy == null || policy.policyId() == null || policy.policyId().isBlank()) {
            throw new GovernanceException(GovernanceException.Kind.POLICY_INVALID, "policyId required");
        }
        if (policy.artifactIdPattern() != null) {
            try {
                policy.compilePattern();
            } catch (PatternSyntaxException e) {
                throw new GovernanceException(GovernanceException.Kind.POLICY_INVALID,
                        "policy " + policy.policyId() + " has uncompilable artifactIdPattern: "
                                + e.getDescription());
            }
        }
    }

    /** 集合校验：同优先级制品覆盖范围不得重叠（否则同一制品会有多条最高优先级命中，自相矛盾）。 */
    static void validateAgainst(TrustPolicy candidate, List<TrustPolicy> others,
                                Map<String, TrustedKey> keys) {
        for (TrustPolicy other : others) {
            if (other.priority() == candidate.priority() && overlaps(candidate, other)) {
                throw new GovernanceException(GovernanceException.Kind.POLICY_INVALID,
                        "policy " + candidate.policyId() + " overlaps at same priority "
                                + candidate.priority() + " with policy " + other.policyId()
                                + "; ambiguous winner, refusing to publish");
            }
        }
        requireTrustedKeys(candidate.policyId(), candidate.allowedSignerKeyIds(), keys, "signer");
        requireTrustedKeys(candidate.policyId(), candidate.allowedSbomSignerKeyIds(), keys, "sbom-signer");
    }

    /**
     * 覆盖范围重叠判定（保守、可判定）：任一方匹配全部（pattern 为 null）必然重叠；
     * 正则文本相同则重叠。其它复杂正则交集不做静态求解，但请求期仍会检测到
     * 同优先级多命中并失败关闭（纵深防线）。
     */
    private static boolean overlaps(TrustPolicy a, TrustPolicy b) {
        if (a.artifactIdPattern() == null || b.artifactIdPattern() == null) {
            return true;
        }
        return a.artifactIdPattern().equals(b.artifactIdPattern());
    }

    /** 策略引用的密钥必须当前存在且受信任（未撤销/未过期），否则发布即拒绝。 */
    private static void requireTrustedKeys(String policyId, List<String> keyIds,
                                           Map<String, TrustedKey> keys, String role) {
        if (keyIds == null) {
            return;
        }
        for (String keyId : keyIds) {
            TrustedKey key = keys.get(keyId);
            if (key == null) {
                throw new GovernanceException(GovernanceException.Kind.POLICY_KEY_UNTRUSTED,
                        "policy " + policyId + " references unknown " + role + " key: " + keyId);
            }
            if (key.isRevoked()) {
                throw new GovernanceException(GovernanceException.Kind.POLICY_KEY_UNTRUSTED,
                        "policy " + policyId + " references revoked " + role + " key: " + keyId);
            }
            if (key.isExpiredAt(Instant.now())) {
                throw new GovernanceException(GovernanceException.Kind.POLICY_KEY_UNTRUSTED,
                        "policy " + policyId + " references expired " + role + " key: " + keyId);
            }
        }
    }

    private ConfigurationSnapshot snapshotLocked() {
        long v = configVersion.get();
        long tv = trustStore.version();
        long pv = policyEngine.version();
        return new ConfigurationSnapshot(v, trustStore.snapshot(), policyEngine.snapshot(), tv + "|" + pv);
    }

    /** 调用方必须持有 this 锁；版本递增与快照发布在同一临界区，对外原子可见。 */
    private void republish() {
        long v = configVersion.incrementAndGet();
        published = new ConfigurationSnapshot(v, trustStore.snapshot(), policyEngine.snapshot(),
                trustStore.version() + "|" + policyEngine.version());
    }
}
