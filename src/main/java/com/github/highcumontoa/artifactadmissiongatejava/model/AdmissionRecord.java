package com.github.highcumontoa.artifactadmissiongatejava.model;

/**
 * 准入记录：一次提交对应一条记录，结论一旦落定不可变。
 *
 * @param recordId          记录标识
 * @param requestHash       请求规范化哈希（用于重复提交判重）
 * @param artifactId        制品标识
 * @param status            当前状态
 * @param decision          最终结论；PENDING 时为 null
 * @param configVersion     判定依据的配置版本词牌；null 表示非持久化的归属视图
 * @param attributedRecordId 归属记录标识：证明被挪用时指向其原本那条结论，正常记录为 null
 */
public record AdmissionRecord(
        String recordId,
        String requestHash,
        String artifactId,
        AdmissionStatus status,
        AdmissionDecision decision,
        String configVersion,
        String attributedRecordId) {

    /** 兼容构造：普通记录（无归属）。 */
    public AdmissionRecord(String recordId, String requestHash, String artifactId,
                           AdmissionStatus status, AdmissionDecision decision) {
        this(recordId, requestHash, artifactId, status, decision,
                decision == null ? null : decision.configVersion(), null);
    }

    public AdmissionRecord withDecision(AdmissionDecision d) {
        return new AdmissionRecord(recordId, requestHash, artifactId, d.status(), d);
    }

    /** 是否为非持久化的归属视图（不占新的准入记录）。 */
    public boolean isAttributionView() {
        return attributedRecordId != null;
    }
}
