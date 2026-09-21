package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.github.highcumontoa.artifactadmissiongatejava.api.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.api.BatchAdmissionResponse;
import com.github.highcumontoa.artifactadmissiongatejava.core.admission.AdmissionRepository;
import com.github.highcumontoa.artifactadmissiongatejava.core.batch.BatchAdmissionService;
import com.github.highcumontoa.artifactadmissiongatejava.core.batch.BatchLimits;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** 批量规模上限、耗时上限与失败回滚：不得残留部分状态。 */
class BatchAdmissionTest extends BaseAdmissionTest {

    @Autowired
    private BatchAdmissionService batchService;
    @Autowired
    private AdmissionRepository repository;

    private List<AdmissionRequest> nValidRequests(int n) {
        TestFixtures.KeyMaterial key = registerDefaultKey(TestFixtures.generateRsaKey());
        configureAllowAllPolicy();
        List<AdmissionRequest> items = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            TestFixtures.Bundle b = TestFixtures.writeSignedBundle(
                    tempDir, key, "batch-" + i, BUILD_SOURCE, ARTIFACT_ID,
                    java.time.Instant.now().minusSeconds(10), null, "stmt-batch-" + i,
                    crypto, envelopes, attestations);
            items.add(b.requestNoSbom(POLICY));
        }
        return items;
    }

    @Test
    void batchExceedingSizeLimitRejectedWholesaleWithoutState() {
        int before = repository.all().size();
        List<AdmissionRequest> items = nValidRequests(5);
        BatchLimits limits = new BatchLimits(3, Duration.ofSeconds(10), 0L);

        BatchAdmissionResponse response = batchService.submit(items, limits);
        log.info("[batch] size-limit accepted={} reason={} completed={}/{}",
                response.accepted(), response.failureReason(), response.completed(), response.requested());

        assertFalse(response.accepted());
        assertTrue(response.failureReason().startsWith("BATCH_TOO_LARGE"));
        assertEquals(0, response.completed());
        assertEquals(repository.all().size(), before, "超限批次不得写入任何记录");
    }

    @Test
    void batchWithinLimitsAllAdmitted() {
        List<AdmissionRequest> items = nValidRequests(4);
        BatchAdmissionResponse response = batchService.submit(items,
                new BatchLimits(10, Duration.ofSeconds(10), 0L));
        log.info("[batch] normal accepted={} completed={}", response.accepted(), response.completed());
        assertTrue(response.accepted());
        assertEquals(4, response.completed());
        assertEquals(4, repository.all().size());
    }

    @Test
    void batchExceedingTimeBudgetRollsBackCreatedRecords() {
        int before = repository.all().size();
        List<AdmissionRequest> items = nValidRequests(6);
        // 每项 50ms，总预算 125ms：约能完成 2~3 项后超时
        BatchLimits limits = new BatchLimits(50, Duration.ofMillis(125), 50L);

        BatchAdmissionResponse response = batchService.submit(items, limits);
        log.info("[batch] timeout accepted={} reason={} completed={}/{} recordsAfter={}",
                response.accepted(), response.failureReason(), response.completed(),
                response.requested(), repository.all().size());

        assertFalse(response.accepted());
        assertTrue(response.failureReason().startsWith("BATCH_TIMEOUT"));
        assertTrue(response.completed() < items.size());
        // 超时后本批次创建的记录必须全部回滚
        assertEquals(before, repository.all().size(), "超时失败不得残留部分准入记录");
        assertTrue(response.results().isEmpty(), "超时批次不返回半成品结果");
    }

    @Test
    void emptyBatchRejected() {
        BatchAdmissionResponse response = batchService.submit(List.of(),
                BatchLimits.defaults());
        assertFalse(response.accepted());
        assertTrue(response.failureReason().startsWith("BATCH_TOO_LARGE"));
    }
}
