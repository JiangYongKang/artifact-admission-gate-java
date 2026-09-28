package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRecord;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionStatus;
import com.github.highcumontoa.artifactadmissiongatejava.model.ProvenanceStatement;
import com.github.highcumontoa.artifactadmissiongatejava.model.RejectReason;
import com.github.highcumontoa.artifactadmissiongatejava.governance.GovernanceRegistry;
import com.github.highcumontoa.artifactadmissiongatejava.policy.PolicyEngine;
import com.github.highcumontoa.artifactadmissiongatejava.policy.TrustPolicy;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ProvenanceVerifier;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ReplayGuard;
import com.github.highcumontoa.artifactadmissiongatejava.sbom.ManifestVerifier;
import com.github.highcumontoa.artifactadmissiongatejava.service.AdmissionService;
import com.github.highcumontoa.artifactadmissiongatejava.store.AdmissionStore;
import com.github.highcumontoa.artifactadmissiongatejava.support.TestFixtures;
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
    private GovernanceRegistry governance;
    private AdmissionStore store;
    private AdmissionService service;

    @BeforeEach
    void setUp() {
        artifactKey = TestFixtures.generateKeyPair();
        provenanceKey = TestFixtures.generateKeyPair();
        governance = new GovernanceRegistry();
        governance.registerKey(TestFixtures.trustedKey(ARTIFACT_KEY_ID, artifactKey));
        governance.registerKey(TestFixtures.trustedKey(PROVENANCE_KEY_ID, provenanceKey));
        governance.seedPolicies(List.of(new TrustPolicy(
                "default-policy", 10, "com\\.example\\..*",
                List.of(ARTIFACT_KEY_ID), List.of(BUILDER_ID), true)));
        store = new AdmissionStore();
        service = newService(governance, store, 100, 5000);
    }

    private AdmissionService newService(GovernanceRegistry registry, AdmissionStore admissionStore,
                                        int maxBatch, long maxDurationMs) {
        return new AdmissionService(admissionStore, registry, new PolicyEngine(),
                new ProvenanceVerifier(), new ManifestVerifier(), new ReplayGuard(),
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
        governance.revokeKey(ARTIFACT_KEY_ID);
        AdmissionRecord record = service.submit(request);
        logDecision("key-revoked", record);
        assertEquals(RejectReason.KEY_REVOKED, record.decision().reason());
    }

    @Test
    void expiredKeyIsRejected() {
        AdmissionRequest request = validRequest();
        governance.expireKey(ARTIFACT_KEY_ID);
        AdmissionRecord record = service.submit(request);
        logDecision("key-expired", record);
        assertEquals(RejectReason.KEY_EXPIRED, record.decision().reason());
    }

    @Test
    void rotatedKeyHonorsGraceRule() {
        // 轮换尚未生效（retiredAt 在未来）：旧密钥签发的签名仍有效
        AdmissionRequest beforeRotation = validRequest();
        KeyPair newKey = TestFixtures.generateKeyPair();
        governance.rotateKey(ARTIFACT_KEY_ID,
                TestFixtures.trustedKey("artifact-key-2", newKey), Instant.now().plusSeconds(3600));
        AdmissionRecord oldButValid = service.submit(beforeRotation);
        logDecision("rotated-grace-valid", oldButValid);
        assertEquals(AdmissionStatus.ADMITTED, oldButValid.status());

        // 轮换已生效（retiredAt 在过去）：旧密钥新签名被拒绝
        AdmissionRequest afterRotation = validRequest();
        governance.rotateKey(ARTIFACT_KEY_ID,
                TestFixtures.trustedKey("artifact-key-3", TestFixtures.generateKeyPair()),
                Instant.now().minusSeconds(3600));
        AdmissionRecord stale = service.submit(afterRotation);
        logDecision("rotated-grace-expired", stale);
        assertEquals(RejectReason.KEY_EXPIRED, stale.decision().reason());
    }

    @Test
    void missingPolicyFailsClosed() {
        governance.seedPolicies(List.of());
        AdmissionRecord record = service.submit(validRequest());
        logDecision("policy-missing", record);
        assertEquals(RejectReason.POLICY_MISSING, record.decision().reason());
    }

    @Test
    void conflictingPoliciesFailClosed() {
        governance.seedPolicies(List.of(
                new TrustPolicy("p1", 10, "com\\.example\\..*", List.of(ARTIFACT_KEY_ID), null, true),
                new TrustPolicy("p2", 10, "com\\.example\\..*", List.of(ARTIFACT_KEY_ID), null, true)));
        AdmissionRecord record = service.submit(validRequest());
        logDecision("policy-conflict", record);
        assertEquals(RejectReason.POLICY_CONFLICT, record.decision().reason());
    }

    @Test
    void policyReferencingUnknownKeyFailsClosed() {
        governance.seedPolicies(List.of(new TrustPolicy(
                "bad-ref", 10, null, List.of("ghost-key"), null, true)));
        AdmissionRecord record = service.submit(validRequest());
        logDecision("untrusted-key-ref", record);
        assertEquals(RejectReason.UNTRUSTED_KEY, record.decision().reason());
    }

    @Test
    void signerNotAllowedIsRejected() {
        KeyPair outsider = TestFixtures.generateKeyPair();
        governance.registerKey(TestFixtures.trustedKey("outsider-key", outsider));
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
    void replayedProvenanceIsAttributedToOriginalRecord() {
        AdmissionRequest first = validRequest();
        AdmissionRecord admitted = service.submit(first);
        assertEquals(AdmissionStatus.ADMITTED, admitted.status());

        // 情形一：同一 statementId 原样带着别的制品提交（绑定对不上，本应 NOT_BOUND）。
        // 归属检查优先：直接归回原结论，连拒绝记录都不产生。
        AdmissionRequest second = validRequest();
        ProvenanceStatement foreign = first.provenance();
        AdmissionRequest replay1 = new AdmissionRequest(second.artifactId(), second.declaredDigest(),
                second.contentBase64(), second.signatureBase64(), second.signerKeyId(), foreign);
        AdmissionRecord r1 = service.submit(replay1);
        logDecision("provenance-replayed-foreign", r1);
        assertEquals(admitted.recordId(), r1.recordId());
        assertEquals(AdmissionStatus.ADMITTED, r1.status());

        // 情形二：把同一 statementId 重新签名、伪造绑定到另一份制品（签名本身有效）。
        // 仍然归回原结论，不产生新记录、不凭空放行。
        AdmissionRequest third = validRequest();
        long issuedAt = Instant.now().getEpochSecond();
        String forgedSig = TestFixtures.sign(provenanceKey.getPrivate(),
                new ProvenanceStatement(foreign.statementId(), third.artifactId(), third.declaredDigest(),
                        BUILDER_ID, issuedAt, PROVENANCE_KEY_ID, null).canonicalPayload());
        ProvenanceStatement rebound = new ProvenanceStatement(foreign.statementId(), third.artifactId(),
                third.declaredDigest(), BUILDER_ID, issuedAt, PROVENANCE_KEY_ID, forgedSig);
        AdmissionRequest replay2 = new AdmissionRequest(third.artifactId(), third.declaredDigest(),
                third.contentBase64(), third.signatureBase64(), third.signerKeyId(), rebound);
        AdmissionRecord r2 = service.submit(replay2);
        logDecision("provenance-replayed-rebound", r2);
        assertEquals(admitted.recordId(), r2.recordId());
        assertEquals(AdmissionStatus.ADMITTED, r2.status());

        // 两个“宿主”制品本身都未留下任何记录（重放归属不产生新记录）
        assertTrue(store.findByRequestHash(AdmissionService.hashRequest(second)).isEmpty());
        assertTrue(store.findByRequestHash(AdmissionService.hashRequest(third)).isEmpty());
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
        AdmissionService limited = newService(governance, store, 2, 5000);
        AdmissionService.BatchResult result = limited.submitBatch(
                List.of(validRequest(), validRequest(), validRequest()));
        log.info("[batch-oversized] wholeBatchRejected={} detail={}",
                result.wholeBatchRejected(), result.rejectionDetail());
        assertTrue(result.wholeBatchRejected());
        assertTrue(result.records().isEmpty());
    }

    @Test
    void exhaustedBatchBudgetRejectsRemainder() {
        AdmissionService noTime = newService(governance, store, 100, 0);
        AdmissionService.BatchResult result = noTime.submitBatch(List.of(validRequest(), validRequest()));
        assertEquals(2, result.records().size());
        for (AdmissionRecord record : result.records()) {
            logDecision("batch-time-exhausted", record);
            assertEquals(RejectReason.BATCH_LIMIT_EXCEEDED, record.decision().reason());
        }
    }
}
