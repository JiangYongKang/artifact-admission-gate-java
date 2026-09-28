package com.github.highcumontoa.artifactadmissiongatejava.api.dto;

import java.util.List;

/**
 * 运行期发布/替换策略请求。null 列表表示该维度不限制；空列表表示显式禁止一切。
 */
public record PolicyUpsertRequest(
        String policyId,
        Integer priority,
        String artifactIdPattern,
        List<String> allowedSignerKeyIds,
        List<String> allowedBuilderIds,
        List<String> allowedSbomSignerKeyIds,
        List<String> allowedComponents,
        boolean requireProvenance,
        boolean requireSbom) {
}
