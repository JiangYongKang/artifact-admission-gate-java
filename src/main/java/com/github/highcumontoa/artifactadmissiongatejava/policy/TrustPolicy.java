package com.github.highcumontoa.artifactadmissiongatejava.policy;

import java.util.List;
import java.util.regex.Pattern;

/**
 * 信任策略：对签名者、构建来源与制品标识的约束。
 * 约束字段为 null 表示该维度不做限制；空列表表示显式禁止一切（与 null 语义不同，可构成冲突检测依据）。
 *
 * @param policyId          策略标识
 * @param priority          优先级，数值小者优先；同优先级多条策略同时命中即视为冲突
 * @param artifactIdPattern 制品标识匹配正则，null 表示匹配全部
 * @param allowedSignerKeyIds 允许的签名密钥标识集合；null 不限制，空列表禁止一切
 * @param allowedBuilderIds   允许的构建来源集合；null 不限制，空列表禁止一切
 * @param requireProvenance   是否强制要求来源证明
 */
public record TrustPolicy(
        String policyId,
        int priority,
        String artifactIdPattern,
        List<String> allowedSignerKeyIds,
        List<String> allowedBuilderIds,
        boolean requireProvenance) {

    public boolean matchesArtifact(String artifactId) {
        return artifactIdPattern == null || Pattern.matches(artifactIdPattern, artifactId);
    }

    public boolean allowsSigner(String keyId) {
        return allowedSignerKeyIds == null || allowedSignerKeyIds.contains(keyId);
    }

    public boolean allowsBuilder(String builderId) {
        return allowedBuilderIds == null || allowedBuilderIds.contains(builderId);
    }
}
