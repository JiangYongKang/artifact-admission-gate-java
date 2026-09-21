package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRecord;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionStatus;
import com.github.highcumontoa.artifactadmissiongatejava.model.ProvenanceStatement;
import com.github.highcumontoa.artifactadmissiongatejava.model.RejectReason;
import com.github.highcumontoa.artifactadmissiongatejava.policy.PolicyEngine;
import com.github.highcumontoa.artifactadmissiongatejava.policy.TrustPolicy;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ProvenanceVerifier;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ReplayGuard;
import com.github.highcumontoa.artifactadmissiongatejava.service.AdmissionService;
import com.github.highcumontoa.artifactadmissiongatejava.store.AdmissionStore;
import com.github.highcumontoa.artifactadmissiongatejava.support.TestFixtures;
import com.github.highcumontoa.artifactadmissiongatejava.trust.TrustStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 准入校验全场景测试：每个用例打印输入摘要与判定依据，保证结论可追溯。
 */
class AdmissionServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AdmissionServiceTest.class);
    private static final String ARTIFACT_KEY_ID = "artifact-key-1";
    private static final String PROVENANCE_KEY_ID = "provenance-key-1";
    private static final String BUILDER_ID = "builder-ci";

    private KeyPair artifactKey;
    private KeyPair provenanceKey;
    private TrustStore trustStore;
    private PolicyEngine policyEngine;
    private AdmissionService service;

    @BeforeEach
    void setUp() {
        artifactKey = TestFixtures.generateKeyPair();
        provenanceKey = TestFixtures.generateKeyPair();
        trustStore = new TrustStore();
        trustStore.register(TestFixtures.trustedKey(ARTIFACT_KEY_ID, artifactKey));
        trustStore.register(TestFixtures.trustedKey(PROVENANCE_KEY_ID, provenanceKey));
        policyEngine = new PolicyEngine();
        policyEngine.setPolicies(List.of(new TrustPolicy(
                "default-policy", 10, "com\\.example\\..*",
                List.of(ARTIFACT_KEY_ID), List.of(BUILDER_ID), true)));
        service = newService(policyEngine, 100, 5000);
    }

    private AdmissionService newService(PolicyEngine engine, int maxBatch, long maxDurationMs) {
        return new AdmissionService(new AdmissionStore(), trustStore, engine,
                new ProvenanceVerifier(), new ReplayGuard(),
                Clock.fixed(Instant.now(), ZoneOffset.UTC), maxBatch, maxDurationMs);
    }

    private AdmissionRequest validRequest() {
        return TestFixtures.validRequest("com.example.app", artifactKey, ARTIFACT_KEY_ID,
                provenanceKey, PROVENANCE_KEY_ID, BUILDER_ID);
    }

    private void logDecision(String caseName, AdmissionRecord record) {
        log.info("[{}] recordId={} status={} reason={} inputDigest={} basis={}",
                caseName, record.recordId(), record.status(),
                record.decision() == null ? null : record.decision().reason(),
                record.decision() == null ? null : record.decision().computedDigest(),
                record.decision() == null ? null : record.decision().detail());
    }

    @Test
    void validRequestIsAdmitted() {
        AdmissionRecord record = service.submit(validRequest());
        logDecision("valid", record);
        assertEquals(AdmissionStatus.ADMITTED, record.status());
        assertNull(record.decision().reason());
    }

    @Test
    void tamperedDigestIsRejected() {
        AdmissionRequest request = validRequest();
        AdmissionRequest tampered = new AdmissionRequest(request.artifactId(),
                "0".repeat(64), request.contentBase64(), request.signatureBase64(),
                request.signerKeyId(), request.provenance());
        AdmissionRecord record = service.submit(tampered);
        logDecision("digest-tampered", record);
        assertEquals(AdmissionStatus.REJECTED, record.status());
        assertEquals(RejectReason.DIGEST_MISMATCH, record.decision().reason());
    }

    @Test
    void forgedSignatureIsRejected() {
        KeyPair attacker = TestFixtures.generateKeyPair();
        AdmissionRequest request = validRequest();
        String forged = TestFixtures.sign(attacker.getPrivate(), request.declaredDigest());
        AdmissionRecord record = service.submit(new AdmissionRequest(request.artifactId(),
                request.declaredDigest(), request.contentBase64(), forged,
                request.signerKeyId(), request.provenance()));
        logDecision("forged-signature", record);
        assertEquals(RejectReason.SIGNATURE_INVALID, record.decision().reason());
    }

    @Test
    void missingProvenanceIsRejected() {
        AdmissionRequest request = validRequest();
        AdmissionRecord record = service.submit(new AdmissionRequest(request.artifactId(),
                request.declaredDigest(), request.contentBase64(), request.signatureBase64(),
                request.signerKeyId(), null));
        logDecision("provenance-missing", record);
        assertEquals(RejectReason.PROVENANCE_MISSING, record.decision().reason());
    }

    @Test
    void unboundProvenanceIsRejected() {
        AdmissionRequest request = validRequest();
        ProvenanceStatement foreign = TestFixtures.provenance("com.example.other",
                request.declaredDigest(), BUILDER_ID, provenanceKey, PROVENANCE_KEY_ID);
        AdmissionRecord record = service.submit(new AdmissionRequest(request.artifactId(),
                request.declaredDigest(), request.contentBase64(), request.signatureBase64(),
                request.signerKeyId(), foreign));
        logDecision("provenance-not-bound", record);
        assertEquals(RejectReason.PROVENANCE_NOT_BOUND, record.decision().reason());
    }

    @Test
    void forgedProvenanceSignatureIsRejected() {
        AdmissionRequest request = validRequest();
        KeyPair attacker = TestFixtures.generateKeyPair();
        ProvenanceStatement p = request.provenance();
        ProvenanceStatement forged = new ProvenanceStatement(p.statementId(), p.artifactId(),
                p.artifactDigest(), p.builderId(), p.issuedAtEpochSeconds(), p.signerKeyId(),
                TestFixtures.sign(attacker.getPrivate(), p.canonicalPayload()));
        AdmissionRecord record = service.submit(new AdmissionRequest(request.artifactId(),
                request.declaredDigest(), request.contentBase64(), request.signatureBase64(),
                request.signerKeyId(), forged));
        logDecision("forged-provenance", record);
        assertEquals(RejectReason.PROVENANCE_UNTRUSTED, record.decision().reason());
    }

    @Test
    void revokedKeyIsRejected() {
        AdmissionRequest request = validRequest();
        trustStore.revoke(ARTIFACT_KEY_ID);
        AdmissionRecord record = service.submit(request);
        logDecision("key-revoked", record);
        assertEquals(RejectReason.KEY_REVOKED, record.decision().reason());
    }

    @Test
    void expiredKeyIsRejected() {
        AdmissionRequest request = validRequest();
        trustStore.expire(ARTIFACT_KEY_ID);
        AdmissionRecord record = service.submit(request);
        logDecision("key-expired", record);
        assertEquals(RejectReason.KEY_EXPIRED, record.decision().reason());
    }

    @Test
    void rotatedKeyHonorsGraceRule() {
        // 轮换尚未生效（retiredAt 在未来）：旧密钥签发的签名仍有效
        AdmissionRequest beforeRotation = validRequest();
        KeyPair newKey = TestFixtures.generateKeyPair();
        trustStore.rotate(ARTIFACT_KEY_ID,
                TestFixtures.trustedKey("artifact-key-2", newKey), Instant.now().plusSeconds(3600));
        AdmissionRecord oldButValid = service.submit(beforeRotation);
        logDecision("rotated-grace-valid", oldButValid);
        assertEquals(AdmissionStatus.ADMITTED, oldButValid.status());

        // 轮换已生效（retiredAt 在过去）：旧密钥新签名被拒绝
        AdmissionRequest afterRotation = validRequest();
        trustStore.rotate(ARTIFACT_KEY_ID,
                TestFixtures.trustedKey("artifact-key-3", TestFixtures.generateKeyPair()),
                Instant.now().minusSeconds(3600));
        AdmissionRecord stale = service.submit(afterRotation);
        logDecision("rotated-grace-expired", stale);
        assertEquals(RejectReason.KEY_EXPIRED, stale.decision().reason());
    }

    @Test
    void missingPolicyFailsClosed() {
        policyEngine.setPolicies(List.of());
        AdmissionRecord record = service.submit(validRequest());
        logDecision("policy-missing", record);
        assertEquals(RejectReason.POLICY_MISSING, record.decision().reason());
    }

    @Test
    void conflictingPoliciesFailClosed() {
        policyEngine.setPolicies(List.of(
                new TrustPolicy("p1", 10, "com\\.example\\..*", List.of(ARTIFACT_KEY_ID), null, true),
                new TrustPolicy("p2", 10, "com\\.example\\..*", List.of(ARTIFACT_KEY_ID), null, true)));
        AdmissionRecord record = service.submit(validRequest());
        logDecision("policy-conflict", record);
        assertEquals(RejectReason.POLICY_CONFLICT, record.decision().reason());
    }

    @Test
    void policyReferencingUnknownKeyFailsClosed() {
        policyEngine.setPolicies(List.of(new TrustPolicy(
                "bad-ref", 10, null, List.of("ghost-key"), null, true)));
        AdmissionRecord record = service.submit(validRequest());
        logDecision("untrusted-key-ref", record);
        assertEquals(RejectReason.UNTRUSTED_KEY, record.decision().reason());
    }

    @Test
    void signerNotAllowedIsRejected() {
        KeyPair outsider = TestFixtures.generateKeyPair();
        trustStore.register(TestFixtures.trustedKey("outsider-key", outsider));
        AdmissionRequest request = TestFixtures.validRequest("com.example.app",
                outsider, "outsider-key", provenanceKey, PROVENANCE_KEY_ID, BUILDER_ID);
        AdmissionRecord record = service.submit(request);
        logDecision("signer-not-allowed", record);
        assertEquals(RejectReason.SIGNER_NOT_ALLOWED, record.decision().reason());
    }

    @Test
    void duplicateSubmissionIsIdempotent() {
        AdmissionRequest request = validRequest();
        AdmissionRecord first = service.submit(request);
        AdmissionRecord second = service.submit(request);
        logDecision("duplicate-first", first);
        logDecision("duplicate-second", second);
        assertEquals(first.recordId(), second.recordId());
        assertEquals(first.status(), second.status());
    }

    @Test
    void replayedProvenanceIsRejected() {
        AdmissionRequest first = validRequest();
        AdmissionRecord admitted = service.submit(first);
        assertEquals(AdmissionStatus.ADMITTED, admitted.status());

        // 同一证明被绑定到另一制品再次提交：不得产生新的放行
        AdmissionRequest second = validRequest();
        AdmissionRequest replay = new AdmissionRequest(second.artifactId(), second.declaredDigest(),
                second.contentBase64(), second.signatureBase64(), second.signerKeyId(), first.provenance());
        AdmissionRecord replayed = service.submit(replay);
        logDecision("provenance-replayed", replayed);
        assertEquals(RejectReason.PROVENANCE_NOT_BOUND, replayed.decision().reason());

        // 即使绑定关系被伪造一致，重放仍被拒绝
        AdmissionRequest third = validRequest();
        ProvenanceStatement reused = new ProvenanceStatement(first.provenance().statementId(),
                third.artifactId(), third.declaredDigest(), BUILDER_ID,
                first.provenance().issuedAtEpochSeconds(), PROVENANCE_KEY_ID,
                TestFixtures.sign(provenanceKey.getPrivate(),
                        new ProvenanceStatement(first.provenance().statementId(), third.artifactId(),
                                third.declaredDigest(), BUILDER_ID,
                                first.provenance().issuedAtEpochSeconds(), PROVENANCE_KEY_ID, null)
                                .canonicalPayload()));
        AdmissionRecord replayed2 = service.submit(new AdmissionRequest(third.artifactId(),
                third.declaredDigest(), third.contentBase64(), third.signatureBase64(),
                third.signerKeyId(), reused));
        logDecision("provenance-replayed-bound", replayed2);
        assertEquals(RejectReason.PROVENANCE_REPLAYED, replayed2.decision().reason());
    }

    @Test
    void concurrentSubmissionsAreConsistent() throws InterruptedException {
        int threads = 16;
        AdmissionRequest shared = validRequest();
        List<AdmissionRequest> distinct = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            distinct.add(TestFixtures.validRequest("com.example.app-" + i, artifactKey, ARTIFACT_KEY_ID,
                    provenanceKey, PROVENANCE_KEY_ID, BUILDER_ID));
        }
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<AdmissionRecord> results = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<Throwable> errors = new ConcurrentLinkedQueue<>();
        for (int i = 0; i < threads; i++) {
            final int index = i;
            pool.submit(() -> {
                try {
                    start.await();
                    // 一半线程提交同一请求（幂等），一半提交各自请求
                    results.add(service.submit(index % 2 == 0 ? shared : distinct.get(index)));
                } catch (Throwable t) {
                    errors.add(t);
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        assertTrue(errors.isEmpty(), "concurrent errors: " + errors);

        List<AdmissionRecord> sharedRecords = results.stream()
                .filter(r -> r.artifactId().equals(shared.artifactId())).toList();
        // 同一请求并发提交：记录串号检查——所有结果必须是同一条记录
        assertTrue(sharedRecords.stream().map(AdmissionRecord::recordId).distinct().count() == 1,
                "duplicate request must resolve to a single record");
        // 所有并发结论均为终态且可解释
        for (AdmissionRecord record : results) {
            assertNotNull(record.decision());
            assertTrue(record.status() == AdmissionStatus.ADMITTED
                    || record.status() == AdmissionStatus.REJECTED);
        }
        log.info("[concurrency] total={} sharedRecordId={} allTerminal=true",
                results.size(), sharedRecords.get(0).recordId());
    }

    @Test
    void oversizedBatchIsRejectedWholly() {
        AdmissionService limited = newService(policyEngine, 2, 5000);
        AdmissionService.BatchResult result = limited.submitBatch(
                List.of(validRequest(), validRequest(), validRequest()));
        log.info("[batch-oversized] wholeBatchRejected={} detail={}",
                result.wholeBatchRejected(), result.rejectionDetail());
        assertTrue(result.wholeBatchRejected());
        assertTrue(result.records().isEmpty());
    }

    @Test
    void exhaustedBatchBudgetRejectsRemainder() {
        AdmissionService noTime = newService(policyEngine, 100, 0);
        AdmissionService.BatchResult result = noTime.submitBatch(List.of(validRequest(), validRequest()));
        assertEquals(2, result.records().size());
        for (AdmissionRecord record : result.records()) {
            logDecision("batch-time-exhausted", record);
            assertEquals(RejectReason.BATCH_LIMIT_EXCEEDED, record.decision().reason());
        }
    }
}
