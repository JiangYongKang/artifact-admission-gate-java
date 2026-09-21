package com.github.highcumontoa.artifactadmissiongatejava.core.crypto;

import java.nio.file.Path;

/** 签名信封的本地 JSON 读写。 */
public interface EnvelopeCodec {
    SignatureEnvelope read(Path file);
    void write(Path file, SignatureEnvelope envelope);
}
