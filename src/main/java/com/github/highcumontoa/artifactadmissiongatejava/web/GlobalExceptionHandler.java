package com.github.highcumontoa.artifactadmissiongatejava.web;

import com.github.highcumontoa.artifactadmissiongatejava.api.ErrorResponse;
import com.github.highcumontoa.artifactadmissiongatejava.core.admission.AdmissionException;
import com.github.highcumontoa.artifactadmissiongatejava.domain.RejectReason;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.NoSuchElementException;

/** 统一错误归类；任何异常都不向调用方泄漏堆栈或密钥材料。 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AdmissionException.class)
    public ResponseEntity<ErrorResponse> handleAdmission(AdmissionException ex, HttpServletRequest request) {
        HttpStatus status = ex.getReason() == RejectReason.BAD_REQUEST ? HttpStatus.BAD_REQUEST : HttpStatus.CONFLICT;
        return body(status, ex.getReason().name(), ex.getMessage(), request);
    }

    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<ErrorResponse> handleNotFound(NoSuchElementException ex, HttpServletRequest request) {
        return body(HttpStatus.NOT_FOUND, "NOT_FOUND", ex.getMessage(), request);
    }

    @ExceptionHandler({IllegalArgumentException.class, HttpMessageNotReadableException.class})
    public ResponseEntity<ErrorResponse> handleBadRequest(Exception ex, HttpServletRequest request) {
        return body(HttpStatus.BAD_REQUEST, RejectReason.BAD_REQUEST.name(), ex.getMessage(), request);
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<ErrorResponse> handleConflict(IllegalStateException ex, HttpServletRequest request) {
        return body(HttpStatus.CONFLICT, "INVALID_STATE", ex.getMessage(), request);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handle(Exception ex, HttpServletRequest request) {
        // 兜底：失败关闭，只回泛化信息，详细堆栈仅进服务端日志
        log.error("unhandled-error path={}", request.getRequestURI(), ex);
        return body(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "request-failed-closed", request);
    }

    private ResponseEntity<ErrorResponse> body(HttpStatus status, String code, String message,
                                               HttpServletRequest request) {
        return ResponseEntity.status(status).body(
                new ErrorResponse(code, message, request.getRequestURI(), Instant.now()));
    }
}
