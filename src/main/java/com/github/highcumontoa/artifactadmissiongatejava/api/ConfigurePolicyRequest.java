package com.github.highcumontoa.artifactadmissiongatejava.api;

import com.github.highcumontoa.artifactadmissiongatejava.core.policy.TrustPolicy;

/** 策略配置请求。 */
public record ConfigurePolicyRequest(TrustPolicy policy) {
}
