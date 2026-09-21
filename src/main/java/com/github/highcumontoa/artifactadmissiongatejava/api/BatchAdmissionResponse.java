package com.github.highcumontoa.artifactadmissiongatejava.api;

import java.util.List;

/** 批量准入结论：整体受规模与耗时上限约束，失败时不残留部分状态。 */
public record BatchAdmissionResponse(
        boolean accepted,
        int requested,
        int completed,
        String failureReason,
        List<AdmissionResponse> results
) {
}
