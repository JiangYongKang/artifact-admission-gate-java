package com.github.highcumontoa.artifactadmissiongatejava.domain;

/**
 * 准入结论状态。系统中只允许出现这三种可解释状态，不允许出现其他中间态。
 */
public enum AdmissionStatus {
    /** 已受理，校验进行中（仅在校验事务窗口内短暂出现，外部查询可见时必带解释性结论） */
    PENDING,
    /** 已放行 */
    ADMITTED,
    /** 已拒绝（拒绝原因见 RejectReason） */
    REJECTED
}
