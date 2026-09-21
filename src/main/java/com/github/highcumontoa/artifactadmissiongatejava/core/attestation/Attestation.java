package com.github.highcumontoa.artifactadmissiongatejava.core.attestation;

import com.github.highcumontoa.artifactadmissiongatejava.core.crypto.SignatureEnvelope;

import java.time.Instant;

/**
 * 来源证明（in-toto 风格的本地模拟）。
 * 证明通过内嵌的签名信封绑定到 artifactDigest；statementId 用于重放防护。
 */
public record Attestation(
        String statementId,
        String artifactDigest,
        String sbomDigest,
        ProvenanceClaims claims,
        Instant issuedAt,
        SignatureEnvelope signature
) {
}
