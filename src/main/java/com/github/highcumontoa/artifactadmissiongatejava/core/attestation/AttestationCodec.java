package com.github.highcumontoa.artifactadmissiongatejava.core.attestation;

import java.nio.file.Path;

/** 来源证明的本地 JSON 读写。 */
public interface AttestationCodec {
    Attestation read(Path file);
    void write(Path file, Attestation attestation);
}
