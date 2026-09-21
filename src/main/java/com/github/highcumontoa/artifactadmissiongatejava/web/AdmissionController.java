package com.github.highcumontoa.artifactadmissiongatejava.web;

import com.github.highcumontoa.artifactadmissiongatejava.api.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.api.AdmissionResponse;
import com.github.highcumontoa.artifactadmissiongatejava.api.BatchAdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.api.BatchAdmissionResponse;
import com.github.highcumontoa.artifactadmissiongatejava.config.GateProperties;
import com.github.highcumontoa.artifactadmissiongatejava.core.admission.AdmissionService;
import com.github.highcumontoa.artifactadmissiongatejava.core.batch.BatchAdmissionService;
import com.github.highcumontoa.artifactadmissiongatejava.core.batch.BatchLimits;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

/** 准入提交与结论查询入口；所有响应均为可解释的终态或明确错误。 */
@RestController
@RequestMapping("/api/admissions")
public class AdmissionController {

    private final AdmissionService admissionService;
    private final BatchAdmissionService batchAdmissionService;
    private final GateProperties properties;

    public AdmissionController(AdmissionService admissionService,
                               BatchAdmissionService batchAdmissionService,
                               GateProperties properties) {
        this.admissionService = admissionService;
        this.batchAdmissionService = batchAdmissionService;
        this.properties = properties;
    }

    @PostMapping
    public AdmissionResponse submit(@RequestBody AdmissionRequest request) {
        return admissionService.submit(request);
    }

    @GetMapping("/{admissionId}")
    public AdmissionResponse query(@PathVariable String admissionId) {
        return admissionService.query(admissionId);
    }

    @PostMapping("/batch")
    public BatchAdmissionResponse batch(@RequestBody BatchAdmissionRequest request) {
        BatchLimits limits = new BatchLimits(properties.getBatchMaxItems(),
                Duration.ofMillis(properties.getBatchTimeBudgetMillis()), 0L);
        return batchAdmissionService.submit(request.items(), limits);
    }
}
