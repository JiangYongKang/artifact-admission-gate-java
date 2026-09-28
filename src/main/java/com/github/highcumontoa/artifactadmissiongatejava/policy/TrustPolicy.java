package com.github.highcumontoa.artifactadmissiongatejava.policy;

import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 信任策略：对签名者、构建来源、制品标识与软件成分的约束。
 * 约束列表字段为 null 表示该维度不做限制；空列表表示显式禁止一切（与 null 语义不同，可构成冲突检测依据）。
 *
 * @param policyId                 策略标识
 * @param priority                 优先级，数值小者优先；同优先级多条策略同时命中即视为冲突
 * @param artifactIdPattern        制品标识匹配正则，null 表示匹配全部
 * @param allowedSignerKeyIds      允许的签名密钥标识集合；null 不限制，空列表禁止一切
 * @param allowedBuilderIds        允许的构建来源集合；null 不限制，空列表禁止一切
 * @param requireProvenance        是否强制要求来源证明
 * @param requireManifest          是否强制要求软件成分清单
 * @param allowedComponentPatterns 允许出现的组件名称正则集合；null 不限制，空列表禁止一切
 */
public record TrustPolicy(
        String policyId,
        int priority,
        String artifactIdPattern,
        List<String> allowedSignerKeyIds,
        List<String> allowedBuilderIds,
        boolean requireProvenance,
        boolean requireManifest,
        List<String> allowedComponentPatterns) {

    /** 兼容无成分约束的旧策略构造：不要求清单、不限制组件。 */
    public TrustPolicy(String policyId, int priority, String artifactIdPattern,
                       List<String> allowedSignerKeyIds, List<String> allowedBuilderIds,
                       boolean requireProvenance) {
        this(policyId, priority, artifactIdPattern, allowedSignerKeyIds, allowedBuilderIds,
                requireProvenance, false, null);
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

    /** 组件名称是否被允许（任一正则命中即可）；null 表示不限制，空列表禁止一切。 */
    public boolean allowsComponent(String componentName) {
        if (allowedComponentPatterns == null) {
            return true;
        }
        for (String regex : allowedComponentPatterns) {
            if (Pattern.matches(regex, componentName)) {
                return true;
            }
        }
        return false;
    }

    /** 自身正则字段是否都可编译；发布期校验用。 */
    public boolean hasValidPatterns() {
        try {
            if (artifactIdPattern != null) {
                Pattern.compile(artifactIdPattern);
            }
            if (allowedComponentPatterns != null) {
                for (String regex : allowedComponentPatterns) {
                    Pattern.compile(regex);
                }
            }
            return true;
        } catch (PatternSyntaxException e) {
            return false;
        }
    }
}
