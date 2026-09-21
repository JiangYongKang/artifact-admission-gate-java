package com.github.highcumontoa.artifactadmissiongatejava.core.policy;

/** 策略约束维度。 */
public enum ConstraintType {
    /** 签名者密钥标识 */
    SIGNER,
    /** 构建来源 */
    BUILD_SOURCE,
    /** 制品标识 */
    ARTIFACT_ID
}
