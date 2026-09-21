package com.github.highcumontoa.artifactadmissiongatejava.core.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;

/** 签名信封 JSON 读写（本地文件模拟）。 */
@Component
public class JacksonEnvelopeCodec implements EnvelopeCodec {

    private final ObjectMapper mapper = JacksonSupport.mapper();

    @Override
    public SignatureEnvelope read(Path file) {
        try {
            return mapper.readValue(Files.readAllBytes(file), SignatureEnvelope.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid-signature-envelope:" + file, e);
        }
    }

    @Override
    public void write(Path file, SignatureEnvelope envelope) {
        try {
            if (file.getParent() != null) {
                Files.createDirectories(file.getParent());
            }
            mapper.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), envelope);
        } catch (Exception e) {
            throw new IllegalStateException("cannot-write-envelope:" + file, e);
        }
    }
}
