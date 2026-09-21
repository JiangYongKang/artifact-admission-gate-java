package com.github.highcumontoa.artifactadmissiongatejava.core.policy;

import com.github.highcumontoa.artifactadmissiongatejava.domain.RejectReason;

import java.util.List;

/** 策略判定结果，basis 记录命中的规则以便追溯。 */
public record PolicyDecision(
        boolean allowed,
        RejectReason reason,
        List<String> basis
) {
}
