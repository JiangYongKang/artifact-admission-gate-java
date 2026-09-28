package com.github.highcumontoa.artifactadmissiongatejava.policy;

import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.model.RejectReason;

import java.util.Comparator;
import java.util.List;

/**
 * 策略引擎（无状态）：在给定的治理快照上按明确优先级组合判定，任何不确定情形失败关闭。
 * 策略集合由 {@link com.github.highcumontoa.artifactadmissiongatejava.governance.GovernanceRegistry}
 * 在运行期管理，本引擎只对某次请求拿到的不可变快照做计算，保证请求内配置视图一致。
 *
 * 判定规则（按序）：
 * 1. 无策略配置 → POLICY_MISSING，拒绝。
 * 2. 取所有匹配制品标识的策略中优先级最高者；若最高优先级存在多条 → POLICY_CONFLICT，拒绝。
 * 3. 命中策略引用了信任快照中不存在的密钥 → UNTRUSTED_KEY，拒绝。
 * 4. 签名者不在允许列表 → SIGNER_NOT_ALLOWED；构建来源不允许 → BUILDER_NOT_ALLOWED。
 */
public class PolicyEngine {

    /** 选择适用策略：失败关闭，绝不默认放行。 */
    public PolicyDecision selectApplicable(List<TrustPolicy> snapshot, String artifactId) {
        if (snapshot.isEmpty()) {
            return PolicyDecision.fail(RejectReason.POLICY_MISSING, "no trust policy configured; failing closed");
        }
        List<TrustPolicy> matching = snapshot.stream()
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

    /** 校验策略引用的密钥是否都存在于当前信任快照；引用未知密钥即失败关闭。 */
    public RejectReason checkKeyReferences(TrustPolicy policy, java.util.function.Predicate<String> keyExists) {
        if (policy.allowedSignerKeyIds() != null) {
            for (String keyId : policy.allowedSignerKeyIds()) {
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
