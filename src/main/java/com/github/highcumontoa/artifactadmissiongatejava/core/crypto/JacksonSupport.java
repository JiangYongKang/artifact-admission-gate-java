package com.github.highcumontoa.artifactadmissiongatejava.core.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

/** 共享 ObjectMapper：ISO-8601 时间、稳定字段顺序，便于本地复现。 */
public final class JacksonSupport {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    private JacksonSupport() {
    }

    public static ObjectMapper mapper() {
        return MAPPER;
    }
}
