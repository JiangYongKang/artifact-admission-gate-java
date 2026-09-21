package com.github.highcumontoa.artifactadmissiongatejava.core.admission;

import com.github.highcumontoa.artifactadmissiongatejava.domain.RejectReason;

/** 准入业务失败（携带可区分原因码，失败关闭语义）。 */
public class AdmissionException extends RuntimeException {

    private final RejectReason reason;

    public AdmissionException(RejectReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public RejectReason getReason() { return reason; }
}
