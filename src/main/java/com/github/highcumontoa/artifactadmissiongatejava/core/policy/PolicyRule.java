package com.github.highcumontoa.artifactadmissiongatejava.core.policy;

/**
 * 一条策略规则：对某约束维度、某个具体取值施加 ALLOW/DENY。
 * precedence 数值越大优先级越高；同优先级上的冲突按失败关闭处理。
 */
public record PolicyRule(
        String id,
        ConstraintType constraint,
        String value,
        Effect effect,
        int precedence
) {
}
