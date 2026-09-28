package com.github.highcumontoa.artifactadmissiongatejava.policy;

import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.model.RejectReason;

import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 策略引擎：按明确优先级组合判定，任何不确定情形失败关闭。
 * 变更经 {@link #mutate(java.util.function.Function)} 串行化并递增版本；
 * 判定规则（按序）：
 * 1. 无策略配置 → POLICY_MISSING，拒绝。
 * 2. 取所有匹配制品标识的策略中优先级最高者；若最高优先级存在多条 → POLICY_CONFLICT，拒绝。
 * 3. 命中策略引用了信任库中不存在的密钥 → UNTRUSTED_KEY，拒绝。
 * 4. 签名者不在允许列表 → SIGNER_NOT_ALLOWED；构建来源不允许 → BUILDER_NOT_ALLOWED。
 */
public class PolicyEngine {

    private final List<TrustPolicy> policies = new CopyOnWriteArrayList<>();
    private final AtomicLong version = new AtomicLong(0);
    private final Object writeLock = new Object();

    public void setPolicies(List<TrustPolicy> newPolicies) {
        synchronized (writeLock) {
            policies.clear();
            policies.addAll(newPolicies);
            version.incrementAndGet();
        }
    }

    /** 新增策略；同 ID 已存在返回 false。 */
    public boolean add(TrustPolicy policy) {
        synchronized (writeLock) {
            if (policies.stream().anyMatch(p -> p.policyId().equals(policy.policyId()))) {
                return false;
            }
            policies.add(policy);
            version.incrementAndGet();
            return true;
        }
    }

    /** 替换同 ID 策略；不存在返回 false。 */
    public boolean replace(TrustPolicy policy) {
        synchronized (writeLock) {
            int[] idx = {-1};
            for (int i = 0; i < policies.size(); i++) {
                if (policies.get(i).policyId().equals(policy.policyId())) {
                    idx[0] = i;
                    break;
                }
            }
            if (idx[0] < 0) {
                return false;
            }
            policies.set(idx[0], policy);
            version.incrementAndGet();
            return true;
        }
    }

    /** 删除策略；不存在返回 false。 */
    public boolean remove(String policyId) {
        synchronized (writeLock) {
            boolean removed = policies.removeIf(p -> p.policyId().equals(policyId));
            if (removed) {
                version.incrementAndGet();
            }
            return removed;
        }
    }

    /** 当前策略版本号：任何变更后严格递增。 */
    public long version() {
        return version.get();
    }

    /** 当前策略快照（只读视图语义，列表本身不可变副本）。 */
    public List<TrustPolicy> snapshot() {
        return List.copyOf(policies);
    }

    /** 选择适用策略：失败关闭，绝不默认放行。 */
    public PolicyDecision selectApplicable(String artifactId) {
        List<TrustPolicy> current = snapshot();
        if (current.isEmpty()) {
            return PolicyDecision.fail(RejectReason.POLICY_MISSING, "no trust policy configured; failing closed");
        }
        List<TrustPolicy> matching = current.stream()
                .filter(p -> p.matchesArtifact(artifactId))
                .sorted(Comparator.comparingInt(TrustPolicy::priority))
                .toList();
        if (matching.isEmpty()) {
            return PolicyDecision.fail(RejectReason.POLICY_MISSING,
                    "no policy matches artifactId=" + artifactId + "; failing closed");
        }
        int best = matching.get(0).priority();
        List<TrustPolicy> top = matching.stream().filter(p -> p.priority() == best).toList();
        if (top.size() > 1) {
            return PolicyDecision.fail(RejectReason.POLICY_CONFLICT,
                    "multiple policies at priority " + best + " match artifactId=" + artifactId
                            + ": " + top.stream().map(TrustPolicy::policyId).toList());
        }
        return PolicyDecision.ok(top.get(0), "selected policy " + top.get(0).policyId() + " at priority " + best);
    }

    /** 校验策略引用的密钥是否都存在于信任库；引用未知密钥即失败关闭。 */
    public RejectReason checkKeyReferences(TrustPolicy policy, java.util.function.Predicate<String> keyExists) {
        if (policy.allowedSignerKeyIds() != null) {
            for (String keyId : policy.allowedSignerKeyIds()) {
                if (!keyExists.test(keyId)) {
                    return RejectReason.UNTRUSTED_KEY;
                }
            }
        }
        if (policy.allowedSbomSignerKeyIds() != null) {
            for (String keyId : policy.allowedSbomSignerKeyIds()) {
                if (!keyExists.test(keyId)) {
                    return RejectReason.UNTRUSTED_KEY;
                }
            }
        }
        return null;
    }

    /** 在已选定策略下校验请求维度约束。 */
    public RejectReason checkConstraints(TrustPolicy policy, AdmissionRequest request) {
        if (!policy.allowsSigner(request.signerKeyId())) {
            return RejectReason.SIGNER_NOT_ALLOWED;
        }
        if (request.provenance() != null && !policy.allowsBuilder(request.provenance().builderId())) {
            return RejectReason.BUILDER_NOT_ALLOWED;
        }
        return null;
    }
}
