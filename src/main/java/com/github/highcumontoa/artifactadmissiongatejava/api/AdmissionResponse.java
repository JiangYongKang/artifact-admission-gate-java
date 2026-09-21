package com.github.highcumontoa.artifactadmissiongatejava.api;

import com.github.highcumontoa.artifactadmissiongatejava.domain.AdmissionStatus;
import com.github.highcumontoa.artifactadmissiongatejava.domain.RejectReason;

import java.time.Instant;
import java.util.List;

/** 准入结论响应；不含任何无法解释的状态与密钥材料。 */
public record AdmissionResponse(
        String admissionId,
        AdmissionStatus status,
        RejectReason rejectReason,
        String artifactDigest,
        String signerKeyId,
        String statementId,
        String policyId,
        boolean replay,
        int replayCount,
        Instant createdAt,
        Instant decidedAt,
        List<String> auditTrail
) {
}
