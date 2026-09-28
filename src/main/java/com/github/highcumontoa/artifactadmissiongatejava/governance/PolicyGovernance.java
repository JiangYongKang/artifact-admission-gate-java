package com.github.highcumontoa.artifactadmissiongatejava.governance;

import com.github.highcumontoa.artifactadmissiongatejava.policy.TrustPolicy;

import java.util.List;
import java.util.function.Predicate;

/**
 * 策略发布期校验：在策略进入治理状态之前挡住自相矛盾、非法正则、
 * 以及引用当前不受信任密钥的策略。校验无副作用，失败时治理状态保持不变。
 */
public final class PolicyGovernance {

    private PolicyGovernance() {
    }

    /**
     * 校验候选策略。
     *
     * @param candidate 待发布策略
     * @param others    发布后与之共存的其他策略（同 ID 的旧策略将被替换，已排除）
     * @param keyExists 当前信任快照中是否存在某密钥
     * @throws PolicyPublicationException 校验失败（code 为机器可读分类）
     */
    public static void validate(TrustPolicy candidate, List<TrustPolicy> others, Predicate<String> keyExists) {
        if (candidate.policyId() == null || candidate.policyId().isBlank()) {
            throw new PolicyPublicationException("POLICY_ID_INVALID", "policyId must not be blank");
        }
        if (!candidate.hasValidPatterns()) {
            throw new PolicyPublicationException("POLICY_PATTERN_INVALID",
                    "policy " + candidate.policyId() + " contains an uncompilable artifact/component pattern");
        }
        // 空签名者白名单 = 显式禁止一切签名者，任何请求都不可能通过，属于自相矛盾
        if (candidate.allowedSignerKeyIds() != null && candidate.allowedSignerKeyIds().isEmpty()) {
            throw new PolicyPublicationException("POLICY_SELF_CONTRADICTION",
                    "policy " + candidate.policyId() + " allows no signer keys; nothing can ever be admitted");
        }
        // 强制要求来源证明，却把所有构建来源都禁掉，要求无法被满足
        if (candidate.requireProvenance() && candidate.allowedBuilderIds() != null
                && candidate.allowedBuilderIds().isEmpty()) {
            throw new PolicyPublicationException("POLICY_SELF_CONTRADICTION",
                    "policy " + candidate.policyId()
                            + " requires provenance but forbids every builder; requirement is unsatisfiable");
        }
        // 强制要求成分清单，却把所有组件都禁掉，要求无法被满足（空清单也不行）
        if (candidate.requireManifest() && candidate.allowedComponentPatterns() != null
                && candidate.allowedComponentPatterns().isEmpty()) {
            throw new PolicyPublicationException("POLICY_SELF_CONTRADICTION",
                    "policy " + candidate.policyId()
                            + " requires a manifest but forbids every component; requirement is unsatisfiable");
        }
        // 引用当前不受信任的密钥：发布期即挡住，而不是等请求进来才失败
        if (candidate.allowedSignerKeyIds() != null) {
            for (String keyId : candidate.allowedSignerKeyIds()) {
                if (!keyExists.test(keyId)) {
                    throw new PolicyPublicationException("POLICY_KEY_NOT_TRUSTED",
                            "policy " + candidate.policyId() + " references key absent from trust store: " + keyId);
                }
            }
        }
        // 与共存策略的确定性冲突：同一优先级、制品范围必然重叠（pattern 相同）→ 永远冲突
        for (TrustPolicy other : others) {
            if (other.priority() == candidate.priority()
                    && java.util.Objects.equals(other.artifactIdPattern(), candidate.artifactIdPattern())) {
                throw new PolicyPublicationException("POLICY_CONFLICT_AT_PUBLISH",
                        "policy " + candidate.policyId() + " has same priority " + candidate.priority()
                                + " and artifact pattern as existing policy " + other.policyId()
                                + "; they would always conflict at admission");
            }
        }
    }
}
