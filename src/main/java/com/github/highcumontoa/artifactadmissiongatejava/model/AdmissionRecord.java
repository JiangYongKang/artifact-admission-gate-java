package com.github.highcumontoa.artifactadmissiongatejava.model;

/**
 * 准入记录：一次提交在某一配置版本下的终态结论，结论一旦落定不可变。
 * 同一请求在配置变化后复核产生新结论时，另起一条修订记录并通过 supersedesRecordId 串联，
 * 以请求哈希为幂等链的最新记录即为当前结论。
 *
 * @param recordId            记录标识
 * @param requestHash         请求规范化哈希（同一请求的多版结论共享）
 * @param artifactId          制品标识
 * @param status              当前状态
 * @param decision            最终结论
 * @param revision            修订序号，首次为 1
 * @param supersedesRecordId  被本记录取代的上一条记录标识；首版为 null
 */
public record AdmissionRecord(
        String recordId,
        String requestHash,
        String artifactId,
        AdmissionStatus status,
        AdmissionDecision decision,
        int revision,
        String supersedesRecordId) {

    /** 兼容构造：首版记录。 */
    public AdmissionRecord(String recordId, String requestHash, String artifactId,
                           AdmissionStatus status, AdmissionDecision decision) {
        this(recordId, requestHash, artifactId, status, decision, 1, null);
    }
}
