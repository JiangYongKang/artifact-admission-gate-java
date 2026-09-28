package com.github.highcumontoa.artifactadmissiongatejava.api.dto;

import java.util.List;

/**
 * 策略发布请求（JSON）。
 */
public record PolicyRequest(
        String policyId,
        Integer priority,
        String artifactIdPattern,
        List<String> allowedSignerKeyIds,
        List<String> allowedBuilderIds,
        Boolean requireProvenance,
        Boolean requireManifest,
        List<String> allowedComponentPatterns) {
}
