package com.github.highcumontoa.artifactadmissiongatejava.core.trust;

import com.github.highcumontoa.artifactadmissiongatejava.domain.RejectReason;

/** 信任根判定结果。 */
public record TrustVerdict(boolean trusted, RejectReason reason, String keyId) {
    public static TrustVerdict ok(String keyId) { return new TrustVerdict(true, null, keyId); }
}
