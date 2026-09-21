package com.github.highcumontoa.artifactadmissiongatejava.domain;

import java.time.Instant;

/** 审计事件：只记录判定依据与输入摘要，严禁包含任何密钥材料。 */
public record AuditEvent(
        Instant timestamp,
        String admissionId,
        String statementId,
        String artifactDigest,
        AdmissionStatus fromStatus,
        AdmissionStatus toStatus,
        RejectReason rejectReason,
        String detail
) {
}
