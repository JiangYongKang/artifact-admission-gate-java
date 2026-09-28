package com.github.highcumontoa.artifactadmissiongatejava.governance;

import com.github.highcumontoa.artifactadmissiongatejava.policy.TrustPolicy;
import com.github.highcumontoa.artifactadmissiongatejava.trust.TrustedKey;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 信任根 + 策略的统一不可变快照：一次准入请求自始至终使用同一快照，
 * 绝不会出现一半旧配置、一半新配置。
 */
public record GovernanceSnapshot(long version, Map<String, TrustedKey> keys, List<TrustPolicy> policies) {

    public GovernanceSnapshot {
        keys = Map.copyOf(keys);
        policies = List.copyOf(policies);
    }

    public Optional<TrustedKey> findKey(String keyId) {
        return Optional.ofNullable(keys.get(keyId));
    }
}
