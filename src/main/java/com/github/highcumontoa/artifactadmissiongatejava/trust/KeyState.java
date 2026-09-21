package com.github.highcumontoa.artifactadmissiongatejava.trust;

/** 密钥生命周期状态。 */
public enum KeyState {
    /** 正常可用。 */
    ACTIVE,
    /** 已轮换退役：仅对轮换时间点之前签发的签名继续有效（宽限规则）。 */
    RETIRED,
    /** 已撤销：任何签名一律不再通过。 */
    REVOKED,
    /** 已过期：任何签名一律不再通过。 */
    EXPIRED
}
