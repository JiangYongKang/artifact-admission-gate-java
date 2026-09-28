package com.github.highcumontoa.artifactadmissiongatejava.config;

import com.github.highcumontoa.artifactadmissiongatejava.policy.TrustPolicy;
import com.github.highcumontoa.artifactadmissiongatejava.trust.TrustedKey;

import java.util.List;
import java.util.Map;

/**
 * 某一时刻信任根与策略的不可变配置快照。一次准入判定自始至终使用同一快照，
 * 不会出现一半旧配置、一半新配置；快照版本单调递增，改动立即产生新版本。
 *
 * @param version      单调递增的配置版本号，从 0 开始
 * @param keys         信任根条目（keyId -> 不可变条目）
 * @param policies     生效中的策略
 * @param versionToken 版本词牌（信任版本|策略版本），用于记录与幂等键
 */
public record ConfigurationSnapshot(
        long version,
        Map<String, TrustedKey> keys,
        List<TrustPolicy> policies,
        String versionToken) {
}
