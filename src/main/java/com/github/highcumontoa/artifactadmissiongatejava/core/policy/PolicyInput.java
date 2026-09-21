package com.github.highcumontoa.artifactadmissiongatejava.core.policy;

/** 参与策略判定的输入事实。 */
public record PolicyInput(
        String signerKeyId,
        String buildSource,
        String artifactId
) {
}
