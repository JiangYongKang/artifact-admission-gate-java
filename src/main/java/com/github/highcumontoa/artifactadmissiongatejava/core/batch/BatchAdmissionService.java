package com.github.highcumontoa.artifactadmissiongatejava.core.batch;

import com.github.highcumontoa.artifactadmissiongatejava.api.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.api.AdmissionResponse;
import com.github.highcumontoa.artifactadmissiongatejava.api.BatchAdmissionResponse;
import com.github.highcumontoa.artifactadmissiongatejava.core.admission.AdmissionService;
import com.github.highcumontoa.artifactadmissiongatejava.core.admission.AdmissionRepository;
import com.github.highcumontoa.artifactadmissiongatejava.domain.AdmissionRecord;
import com.github.highcumontoa.artifactadmissiongatejava.domain.AdmissionStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 批量准入：
 * - 规模上限：items.size() &gt; maxItems 直接整体拒绝 BATCH_TOO_LARGE，不触碰任何状态；
 * - 耗时上限：逐项处理，超出 timeBudget 即停止并整体失败 BATCH_TIMEOUT，
 *   本批次新建的记录（重放命中的旧记录除外）全部回滚，不残留部分状态；
 * - 逐项之间可注入测试延迟以确定性地复现超时；
 * - 不使用线程池等需要额外清理的资源，避免资源泄漏。
 */
@Service
public class BatchAdmissionService {

    private static final Logger log = LoggerFactory.getLogger(BatchAdmissionService.class);

    private final AdmissionService admissionService;
    private final AdmissionRepository repository;

    public BatchAdmissionService(AdmissionService admissionService, AdmissionRepository repository) {
        this.admissionService = admissionService;
        this.repository = repository;
    }

    public BatchAdmissionResponse submit(List<AdmissionRequest> items, BatchLimits limits) {
        if (items == null || items.isEmpty()) {
            return new BatchAdmissionResponse(false, 0, 0, "BATCH_TOO_LARGE:empty-batch", List.of());
        }
        if (items.size() > limits.maxItems()) {
            log.warn("batch rejected: requested={} exceeds max={}", items.size(), limits.maxItems());
            return new BatchAdmissionResponse(false, items.size(), 0,
                    "BATCH_TOO_LARGE:requested=" + items.size() + ",max=" + limits.maxItems(), List.of());
        }

        long deadlineNanos = System.nanoTime() + limits.timeBudget().toNanos();
        List<AdmissionResponse> results = new ArrayList<>();
        Set<String> createdThisBatch = new HashSet<>();
        int index = 0;
        for (AdmissionRequest item : items) {
            if (System.nanoTime() - deadlineNanos > 0) {
                rollback(createdThisBatch, items.size(), index);
                return new BatchAdmissionResponse(false, items.size(), index,
                        "BATCH_TIMEOUT:after=" + index + "-items,budget=" + limits.timeBudget().toMillis() + "ms",
                        List.of());
            }
            AdmissionResponse response = admissionService.submit(item, createdThisBatch::add);
            results.add(response);
            index++;
            if (limits.perItemDelayMillisForTest() > 0) {
                try {
                    Thread.sleep(limits.perItemDelayMillisForTest());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    rollback(createdThisBatch, items.size(), index);
                    return new BatchAdmissionResponse(false, items.size(), index, "BATCH_TIMEOUT:interrupted", List.of());
                }
            }
        }
        // 整体语义：每一条都 ADMITTED 才视为批次放行；存在拒绝则批次标记失败，但结论逐条可追溯
        boolean allAdmitted = results.stream().allMatch(r -> r.status() == AdmissionStatus.ADMITTED);
        return new BatchAdmissionResponse(allAdmitted, items.size(), results.size(),
                allAdmitted ? null : "BATCH_CONTAINS_REJECTION", List.copyOf(results));
    }

    private void rollback(Set<String> createdThisBatch, int requested, int completed) {
        for (String admissionId : createdThisBatch) {
            repository.remove(admissionId);
        }
        log.warn("batch rolled back: requested={} completed={} removed={}",
                requested, completed, createdThisBatch.size());
    }
}
