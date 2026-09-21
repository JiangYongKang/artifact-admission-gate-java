package com.github.highcumontoa.artifactadmissiongatejava.api;

import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRecord;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.service.AdmissionService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 对外准入接口：提交与结论查询。
 * 响应只含状态、原因与判定依据，绝不包含密钥材料。
 */
@RestController
@RequestMapping("/api/admissions")
public class AdmissionController {

    private final AdmissionService service;

    public AdmissionController(AdmissionService service) {
        this.service = service;
    }

    @PostMapping
    public ResponseEntity<AdmissionRecord> submit(@RequestBody AdmissionRequest request) {
        return ResponseEntity.ok(service.submit(request));
    }

    @PostMapping("/batch")
    public ResponseEntity<?> submitBatch(@RequestBody List<AdmissionRequest> requests) {
        AdmissionService.BatchResult result = service.submitBatch(requests);
        if (result.wholeBatchRejected()) {
            return ResponseEntity.unprocessableEntity().body(Map.of(
                    "status", "REJECTED",
                    "reason", "BATCH_LIMIT_EXCEEDED",
                    "detail", result.rejectionDetail()));
        }
        return ResponseEntity.ok(result.records());
    }

    @GetMapping("/{recordId}")
    public ResponseEntity<AdmissionRecord> query(@PathVariable String recordId) {
        return service.query(recordId)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
