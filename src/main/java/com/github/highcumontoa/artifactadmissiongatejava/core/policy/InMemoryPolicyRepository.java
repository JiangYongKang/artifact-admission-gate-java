package com.github.highcumontoa.artifactadmissiongatejava.core.policy;

import com.github.highcumontoa.artifactadmissiongatejava.core.admission.AdmissionException;
import com.github.highcumontoa.artifactadmissiongatejava.domain.RejectReason;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 内存策略库。策略整体校验后整体发布：任何冲突/非法都失败关闭，旧版本保持不变，
 * 因此并发读取永远只能看到某个完整一致的版本，不会读到半成品。
 */
@Component
public class InMemoryPolicyRepository implements PolicyRepository {

    private final Map<String, TrustPolicy> policies = new ConcurrentHashMap<>();

    @Override
    public void put(TrustPolicy policy) {
        validate(policy);
        policies.put(policy.policyId(), policy);
    }

    @Override
    public TrustPolicy get(String policyId) {
        return policies.get(policyId);
    }

    @Override
    public List<String> policyIds() {
        return new ArrayList<>(policies.keySet());
    }

    /**
     * 冲突规则：同一约束维度、同一取值上若存在两条优先级相同但效果相反的规则，
     * 则无法通过明确优先级消歧，判为策略冲突，失败关闭。
     */
    static void validate(TrustPolicy policy) {
        if (policy == null || policy.policyId() == null || policy.policyId().isBlank()) {
            throw new AdmissionException(RejectReason.POLICY_CONFLICT, "policy-id-required");
        }
        List<PolicyRule> rules = policy.rules();
        if (rules == null || rules.isEmpty()) {
            throw new AdmissionException(RejectReason.POLICY_MISSING, "policy-has-no-rules:" + policy.policyId());
        }
        for (int i = 0; i < rules.size(); i++) {
            PolicyRule a = rules.get(i);
            if (a.constraint() == null || a.value() == null || a.effect() == null || a.id() == null) {
                throw new AdmissionException(RejectReason.POLICY_CONFLICT,
                        "ill-formed-rule@" + i);
            }
            for (int j = i + 1; j < rules.size(); j++) {
                PolicyRule b = rules.get(j);
                boolean sameKey = a.constraint() == b.constraint()
                        && a.value().equals(b.value());
                boolean samePrecedence = a.precedence() == b.precedence();
                boolean opposite = a.effect() != b.effect();
                if (sameKey && samePrecedence && opposite) {
                    throw new AdmissionException(RejectReason.POLICY_CONFLICT,
                            "conflicting-rules:" + a.id() + "<->" + b.id()
                                    + " constraint=" + a.constraint() + " value=" + a.value());
                }
            }
        }
    }
}
