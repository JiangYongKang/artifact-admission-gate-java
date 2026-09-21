package com.github.highcumontoa.artifactadmissiongatejava.domain;

/** 信任根密钥的生命周期状态。 */
public enum KeyState {
    ACTIVE,
    ROTATED,
    REVOKED
}
