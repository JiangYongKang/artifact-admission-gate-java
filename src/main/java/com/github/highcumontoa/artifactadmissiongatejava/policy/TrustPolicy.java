package com.github.highcumontoa.artifactadmissiongatejava.policy;

import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 信任策略：对签名者、构建来源、软件成分清单与制品标识的约束。
 * 约束字段为 null 表示该维度不做限制；空列表表示显式禁止一切（与 null 语义不同，可构成冲突检测依据）。
 *
 * @param policyId               策略标识
 * @param priority               优先级，数值小者优先；同优先级多条策略同时命中即视为冲突
 * @param artifactIdPattern      制品标识匹配正则，null 表示匹配全部
 * @param allowedSignerKeyIds    允许的签名密钥标识集合；null 不限制，空列表禁止一切
 * @param allowedBuilderIds      允许的构建来源集合；null 不限制，空列表禁止一切
 * @param requireProvenance      是否强制要求来源证明
 * @param allowedSbomSignerKeyIds 允许的清单签名密钥；null 表示信任库内任意有效密钥
 * @param allowedComponents      允许的组件（"name" 或 "name:version"）；null 不限制，空列表禁止一切组件
 * @param requireSbom            是否强制要求软件成分清单
 */
public record TrustPolicy(
        String policyId,
        int priority,
        String artifactIdPattern,
        List<String> allowedSignerKeyIds,
        List<String> allowedBuilderIds,
        boolean requireProvenance,
        List<String> allowedSbomSignerKeyIds,
        List<String> allowedComponents,
        boolean requireSbom) {

    /** 兼容构造：不含 SBOM 维度的旧策略。 */
    public TrustPolicy(String policyId, int priority, String artifactIdPattern,
                       List<String> allowedSignerKeyIds, List<String> allowedBuilderIds,
                       boolean requireProvenance) {
        this(policyId, priority, artifactIdPattern, allowedSignerKeyIds, allowedBuilderIds,
                requireProvenance, null, null, false);
    }

    public boolean matchesArtifact(String artifactId) {
        return artifactIdPattern == null || Pattern.matches(artifactIdPattern, artifactId);
    }

    public boolean allowsSigner(String keyId) {
        return allowedSignerKeyIds == null || allowedSignerKeyIds.contains(keyId);
    }

    public boolean allowsBuilder(String builderId) {
        return allowedBuilderIds == null || allowedBuilderIds.contains(builderId);
    }

    public boolean allowsSbomSigner(String keyId) {
        return allowedSbomSignerKeyIds == null || allowedSbomSignerKeyIds.contains(keyId);
    }

    /** 组件允许判定：按 "name" 或 "name:version" 匹配，精确匹配。 */
    public boolean allowsComponent(String name, String version) {
        if (allowedComponents == null) {
            return true;
        }
        if (allowedComponents.contains(name)) {
            return true;
        }
        return version != null && allowedComponents.contains(name + ":" + version);
    }

    /** 编译制品标识正则；非法时抛出 PatternSyntaxException（发布阶段即拒绝）。 */
    public Pattern compilePattern() {
        return artifactIdPattern == null ? null : Pattern.compile(artifactIdPattern);
    }
}
