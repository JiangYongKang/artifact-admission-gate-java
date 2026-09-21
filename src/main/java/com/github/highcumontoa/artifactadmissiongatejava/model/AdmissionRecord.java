package com.github.highcumontoa.artifactadmissiongatejava.model;

/**
 * 准入记录：一次提交对应一条记录，结论一旦落定不可变。
 *
 * @param recordId     记录标识
 * @param requestHash  请求规范化哈希（用于重复提交判重）
 * @param artifactId   制品标识
 * @param status       当前状态
 * @param decision     最终结论；PENDING 时为 null
 */
public record AdmissionRecord(
        String recordId,
        String requestHash,
        String artifactId,
        AdmissionStatus status,
        AdmissionDecision decision) {

    public AdmissionRecord withDecision(AdmissionDecision d) {
        return new AdmissionRecord(recordId, requestHash, artifactId, d.status(), d);
    }
}
