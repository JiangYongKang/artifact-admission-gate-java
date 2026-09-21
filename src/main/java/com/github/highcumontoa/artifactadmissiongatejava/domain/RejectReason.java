package com.github.highcumontoa.artifactadmissiongatejava.domain;

/** 拒绝原因码，每种失败可区分，便于追溯与测试断言。 */
public enum RejectReason {
    DIGEST_MISMATCH,
    SIGNATURE_INVALID,
    ATTESTATION_MISSING,
    ATTESTATION_NOT_BOUND,
    ATTESTATION_MALFORMED,
    KEY_UNTRUSTED,
    KEY_REVOKED,
    KEY_EXPIRED,
    KEY_SUPERSEDED,
    POLICY_MISSING,
    POLICY_CONFLICT,
    POLICY_DENIED,
    SBOM_DIGEST_MISMATCH,
    BATCH_TOO_LARGE,
    BATCH_TIMEOUT,
    BAD_REQUEST
}
