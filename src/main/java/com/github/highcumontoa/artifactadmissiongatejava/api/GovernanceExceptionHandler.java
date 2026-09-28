package com.github.highcumontoa.artifactadmissiongatejava.api;

import com.github.highcumontoa.artifactadmissiongatejava.governance.PolicyPublicationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/** 治理操作异常映射：发布被拒/参数非法返回 422/400，绝不以 5xx 含糊带过。 */
@RestControllerAdvice
public class GovernanceExceptionHandler {

    @ExceptionHandler(PolicyPublicationException.class)
    public ResponseEntity<Map<String, String>> handlePublication(PolicyPublicationException ex) {
        return ResponseEntity.unprocessableEntity().body(Map.of(
                "status", "REJECTED",
                "code", ex.code(),
                "detail", ex.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleIllegalArgument(IllegalArgumentException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                "status", "REJECTED",
                "code", "INVALID_ARGUMENT",
                "detail", ex.getMessage() == null ? "invalid argument" : ex.getMessage()));
    }
}
