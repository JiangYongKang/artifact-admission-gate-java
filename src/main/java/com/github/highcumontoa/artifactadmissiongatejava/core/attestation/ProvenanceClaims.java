package com.github.highcumontoa.artifactadmissiongatejava.core.attestation;

/** 来源声明：构建来源与制品标识，是策略判定的输入。 */
public record ProvenanceClaims(
        String buildSource,
        String artifactId
) {
}
