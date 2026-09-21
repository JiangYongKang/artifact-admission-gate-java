package com.github.highcumontoa.artifactadmissiongatejava.core.attestation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.highcumontoa.artifactadmissiongatejava.core.crypto.JacksonSupport;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;

/** 来源证明 JSON 读写（本地文件模拟）。 */
@Component
public class JacksonAttestationCodec implements AttestationCodec {

    private final ObjectMapper mapper = JacksonSupport.mapper();

    @Override
    public Attestation read(Path file) {
        try {
            return mapper.readValue(Files.readAllBytes(file), Attestation.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid-attestation:" + file, e);
        }
    }

    @Override
    public void write(Path file, Attestation attestation) {
        try {
            if (file.getParent() != null) {
                Files.createDirectories(file.getParent());
            }
            mapper.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), attestation);
        } catch (Exception e) {
            throw new IllegalStateException("cannot-write-attestation:" + file, e);
        }
    }
}
