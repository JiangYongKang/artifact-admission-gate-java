package com.github.highcumontoa.artifactadmissiongatejava.api;

import java.time.Instant;

/** 统一错误响应。 */
public record ErrorResponse(
        String errorCode,
        String message,
        String path,
        Instant timestamp
) {
}
