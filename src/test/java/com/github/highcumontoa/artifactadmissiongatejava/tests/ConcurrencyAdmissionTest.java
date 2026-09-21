package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.github.highcumontoa.artifactadmissiongatejava.api.AdmissionResponse;
import com.github.highcumontoa.artifactadmissiongatejava.core.admission.AdmissionService;
import com.github.highcumontoa.artifactadmissiongatejava.domain.AdmissionStatus;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/** 并发准入：去重原子、结论不串号、全部终态可解释。 */
class ConcurrencyAdmissionTest extends BaseAdmissionTest {

    @Autowired
    private AdmissionService admissionService;

    @Test
    void sameStatementSubmittedConcurrentlyYieldsSingleRecord() throws Exception {
        TestFixtures.KeyMaterial key = registerDefaultKey(TestFixtures.generateRsaKey());
        configureAllowAllPolicy();
        TestFixtures.Bundle bundle = TestFixtures.writeSignedBundle(
                tempDir, key, "conc-same", BUILD_SOURCE, ARTIFACT_ID,
                java.time.Instant.now().minusSeconds(10), null, "stmt-conc-same",
                crypto, envelopes, attestations);

        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        ConcurrentLinkedQueue<AdmissionResponse> responses = new ConcurrentLinkedQueue<>();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    responses.add(admissionService.submit(bundle.requestNoSbom(POLICY)));
                } catch (Exception e) {
                    responses.add(null);
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdownNow();

        Set<String> ids = responses.stream().map(AdmissionResponse::admissionId).collect(Collectors.toSet());
        long admitted = responses.stream().filter(r -> r != null && r.status() == AdmissionStatus.ADMITTED).count();
        long replays = responses.stream().filter(r -> r != null && r.replay()).count();

        log.info("[conc-same] threads={} distinctRecords={} admitted={} replays={}",
                threads, ids.size(), admitted, replays);
        assertEquals(1, ids.size(), "同一证明并发提交只允许产生一条准入记录");
        assertEquals(threads, responses.size());
        assertTrue(responses.stream().noneMatch(r -> r == null));
        assertEquals(threads, admitted);
        assertEquals(threads - 1, replays);
        // 重放计数应在并发下累加到 threads-1，不丢更新；取所有响应中观察到的最大值
        int maxReplay = responses.stream().mapToInt(AdmissionResponse::replayCount).max().orElse(-1);
        assertEquals(threads - 1, maxReplay);
    }

    @Test
    void distinctStatementsConcurrentlyDoNotCrossTalk() throws Exception {
        TestFixtures.KeyMaterial key = registerDefaultKey(TestFixtures.generateRsaKey());
        configureAllowAllPolicy();

        int n = 40;
        List<TestFixtures.Bundle> bundles = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            bundles.add(TestFixtures.writeSignedBundle(
                    tempDir, key, "conc-dist-" + i, BUILD_SOURCE, ARTIFACT_ID,
                    java.time.Instant.now().minusSeconds(10), null, "stmt-conc-dist-" + i,
                    crypto, envelopes, attestations));
        }

        ExecutorService pool = Executors.newFixedThreadPool(12);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<AdmissionResponse> responses = new ConcurrentLinkedQueue<>();
        List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
        for (TestFixtures.Bundle b : bundles) {
            futures.add(pool.submit(() -> {
                try {
                    start.await();
                    responses.add(admissionService.submit(b.requestNoSbom(POLICY)));
                } catch (Exception e) {
                    responses.add(null);
                }
            }));
        }
        start.countDown();
        for (var f : futures) {
            f.get(30, TimeUnit.SECONDS);
        }
        pool.shutdownNow();

        Set<String> ids = new HashSet<>();
        Set<String> digests = new HashSet<>();
        for (AdmissionResponse r : responses) {
            assertNotNull(r);
            assertEquals(AdmissionStatus.ADMITTED, r.status());
            ids.add(r.admissionId());
            digests.add(r.artifactDigest());
        }
        log.info("[conc-dist] requests={} distinctIds={} distinctDigests={}", n, ids.size(), digests.size());
        assertEquals(n, responses.size());
        assertEquals(n, ids.size(), "不同证明必须各自独立成单，不得串号");
        assertEquals(n, digests.size());
    }
}
