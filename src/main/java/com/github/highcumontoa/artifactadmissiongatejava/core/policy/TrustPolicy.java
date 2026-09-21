package com.github.highcumontoa.artifactadmissiongatejava.core.policy;

import java.util.List;

/**
 * 命名信任策略：一组有序规则。
 * 规则在载入时做冲突校验；策略缺失/冲突一律失败关闭。
 */
public record TrustPolicy(
        String policyId,
        List<PolicyRule> rules
) {
}
