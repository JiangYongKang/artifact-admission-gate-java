package com.github.highcumontoa.artifactadmissiongatejava.policy;

import com.github.highcumontoa.artifactadmissiongatejava.model.RejectReason;

/**
 * 策略判定结果。
 *
 * @param applicable 命中的策略；未命中或冲突时为 null
 * @param failure    失败原因；成功时为 null
 * @param detail     判定依据说明
 */
public record PolicyDecision(TrustPolicy applicable, RejectReason failure, String detail) {

    public static PolicyDecision ok(TrustPolicy policy, String detail) {
        return new PolicyDecision(policy, null, detail);
    }

    public static PolicyDecision fail(RejectReason reason, String detail) {
        return new PolicyDecision(null, reason, detail);
    }

    public boolean isAllowed() {
        return failure == null;
    }
}
