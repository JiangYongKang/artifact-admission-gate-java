package com.github.highcumontoa.artifactadmissiongatejava.core.policy;

import com.github.highcumontoa.artifactadmissiongatejava.domain.RejectReason;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * 策略组合判定：
 * 1. 按约束维度（签名者 / 构建来源 / 制品标识）分组；
 * 2. 每个维度只取命中事实的规则，并以最高 precedence 决定该维度结论（明确优先级）；
 * 3. 任一维度为 DENY 即拒绝；所有出现过的维度均 ALLOW 才放行；
 * 4. 某维度事实为空或没有任何规则命中，按失败关闭拒绝 POLICY_DENIED，绝不默认放行。
 *
 * 同优先级冲突在策略发布时已被拦截，此处再次防御性检查（POLICY_CONFLICT）。
 */
@Component
public class PolicyEvaluator {

    public PolicyDecision evaluate(TrustPolicy policy, PolicyInput input) {
        if (policy == null) {
            return new PolicyDecision(false, RejectReason.POLICY_MISSING, List.of("policy=null"));
        }
        Map<ConstraintType, String> facts = new EnumMap<>(ConstraintType.class);
        facts.put(ConstraintType.SIGNER, input.signerKeyId());
        facts.put(ConstraintType.BUILD_SOURCE, input.buildSource());
        facts.put(ConstraintType.ARTIFACT_ID, input.artifactId());

        List<String> basis = new ArrayList<>();
        boolean anyRuleExists = false;

        for (ConstraintType type : ConstraintType.values()) {
            String fact = facts.get(type);
            List<PolicyRule> matched = new ArrayList<>();
            int bestPrecedence = Integer.MIN_VALUE;
            for (PolicyRule rule : policy.rules()) {
                if (rule.constraint() == type && fact != null && fact.equals(rule.value())) {
                    anyRuleExists = true;
                    if (rule.precedence() > bestPrecedence) {
                        bestPrecedence = rule.precedence();
                        matched.clear();
                        matched.add(rule);
                    } else if (rule.precedence() == bestPrecedence) {
                        matched.add(rule);
                    }
                }
            }
            if (matched.isEmpty()) {
                basis.add(type + ":no-match(fact=" + (fact == null ? "<absent>" : fact) + ")->DENY");
                return new PolicyDecision(false, RejectReason.POLICY_DENIED, basis);
            }
            Effect effect = null;
            for (PolicyRule rule : matched) {
                if (effect == null) {
                    effect = rule.effect();
                } else if (effect != rule.effect()) {
                    basis.add(type + ":conflict@precedence=" + bestPrecedence);
                    return new PolicyDecision(false, RejectReason.POLICY_CONFLICT, basis);
                }
            }
            basis.add(matched.get(0).constraint() + ":" + fact + "->" + effect
                    + "(rule=" + matched.get(0).id() + ",p=" + bestPrecedence + ")");
            if (effect == Effect.DENY) {
                return new PolicyDecision(false, RejectReason.POLICY_DENIED, basis);
            }
        }

        if (!anyRuleExists) {
            return new PolicyDecision(false, RejectReason.POLICY_MISSING, List.of("no-applicable-rules"));
        }
        return new PolicyDecision(true, null, basis);
    }
}
