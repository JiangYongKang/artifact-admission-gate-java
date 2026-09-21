package com.github.highcumontoa.artifactadmissiongatejava.model;

/** 准入结论状态机：任何记录在任何时刻必居其一，不存在无法解释的中间态。 */
public enum AdmissionStatus {
    /** 已受理，校验尚未完成（仅在异步/批量窗口内短暂存在）。 */
    PENDING,
    /** 校验通过，制品放行。 */
    ADMITTED,
    /** 校验失败，制品被拒绝，原因见 {@link RejectReason}。 */
    REJECTED
}
