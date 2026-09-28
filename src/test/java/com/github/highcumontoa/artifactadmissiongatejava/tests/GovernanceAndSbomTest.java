package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.github.highcumontoa.artifactadmissiongatejava.config.ConfigurationSnapshot;
import com.github.highcumontoa.artifactadmissiongatejava.config.GovernanceException;
import com.github.highcumontoa.artifactadmissiongatejava.config.GovernanceManager;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRecord;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionStatus;
import com.github.highcumontoa.artifactadmissiongatejava.model.ProvenanceStatement;
import com.github.highcumontoa.artifactadmissiongatejava.model.RejectReason;
import com.github.highcumontoa.artifactadmissiongatejava.model.SbomComponent;
import com.github.highcumontoa.artifactadmissiongatejava.model.SoftwareBillOfMaterials;
import com.github.highcumontoa.artifactadmissiongatejava.policy.PolicyEngine;
import com.github.highcumontoa.artifactadmissiongatejava.policy.TrustPolicy;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ProvenanceVerifier;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ReplayGuard;
import com.github.highcumontoa.artifactadmissiongatejava.service.AdmissionService;
import com.github.highcumontoa.artifactadmissiongatejava.sbom.SbomVerifier;
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
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 运行期配置治理、SBOM 软件成分校验与结论复核测试。
 * 每个用例日志打印输入摘要、配置版本与判定依据（inputDigest=... configVersion=... basis=...）。
 */
class GovernanceAndSbomTest {

    private static final Logger log = LoggerFactory.getLogger(GovernanceAndSbomTest.class);
    private static final String ARTIFACT_KEY_ID = "artifact-key-1";
    private static final String PROVENANCE_KEY_ID = "provenance-key-1";
    private static final String SBOM_KEY_ID = "sbom-key-1";
    private static final String BUILDER_ID = "builder-ci";

    private KeyPair artifactKey;
    private KeyPair provenanceKey;
    private KeyPair sbomKey;
    private TrustStore trustStore;
    private PolicyEngine policyEngine;
    private GovernanceManager governance;
    private AdmissionService service;
    private final Clock clock = Clock.fixed(Instant.now(), ZoneOffset.UTC);

    @BeforeEach
    void setUp() {
        artifactKey = TestFixtures.generateKeyPair();
        provenanceKey = TestFixtures.generateKeyPair();
        sbomKey = TestFixtures.generateKeyPair();
        trustStore = new TrustStore();
        policyEngine = new PolicyEngine();
        governance = new GovernanceManager(trustStore, policyEngine);
        trustStore.register(TestFixtures.trustedKey(ARTIFACT_KEY_ID, artifactKey));
        trustStore.register(TestFixtures.trustedKey(PROVENANCE_KEY_ID, provenanceKey));
        trustStore.register(TestFixtures.trustedKey(SBOM_KEY_ID, sbomKey));
        // 直接用治理器发布基线策略，确保初始版本一致
        governance.publishPolicy(new TrustPolicy("default-policy", 10, "com\\.example\\..*",
                List.of(ARTIFACT_KEY_ID), List.of(BUILDER_ID), true));
        service = new AdmissionService(new AdmissionStore(), governance, trustStore, policyEngine,
                new ProvenanceVerifier(), new SbomVerifier(), new ReplayGuard(), clock, 100, 5000);
    }

    private AdmissionRequest validRequest() {
        return TestFixtures.validRequest("com.example.app", artifactKey, ARTIFACT_KEY_ID,
                provenanceKey, PROVENANCE_KEY_ID, BUILDER_ID);
    }

    private void logDecision(String caseName, AdmissionRecord record) {
        log.info("[{}] recordId={} status={} reason={} inputDigest={} configVersion={} attributedTo={} basis={}",
                caseName, record.recordId(), record.status(),
                record.decision() == null ? null : record.decision().reason(),
                record.decision() == null ? null : record.decision().computedDigest(),
                record.configVersion(), record.attributedRecordId(),
                record.decision() == null ? null : record.decision().detail());
    }

    // ---------- 运行期信任根治理 ----------

    @Test
    void registerKeyAtRuntimeTakesEffectImmediately() {
        KeyPair fresh = TestFixtures.generateKeyPair();
        long before = governance.currentSnapshot().version();
        governance.registerKey(TestFixtures.trustedKey("fresh-key", fresh));
        assertTrue(governance.currentSnapshot().version() > before);
        assertTrue(governance.currentSnapshot().keys().containsKey("fresh-key"));
        AdmissionRequest request = TestFixtures.validRequest("com.example.app",
                fresh, "fresh-key", provenanceKey, PROVENANCE_KEY_ID, BUILDER_ID);
        // 新密钥尚未被策略允许 -> SIGNER_NOT_ALLOWED
        AdmissionRecord rejected = service.submit(request);
        logDecision("runtime-key-not-allowed", rejected);
        assertEquals(RejectReason.SIGNER_NOT_ALLOWED, rejected.decision().reason());

        // 发布替换策略允许新密钥后，同样输入立刻放行（无需重启）
        governance.replacePolicy(new TrustPolicy("default-policy", 10, "com\\.example\\..*",
                List.of("fresh-key"), List.of(BUILDER_ID), true));
        AdmissionRecord admitted = service.submit(request);
        logDecision("runtime-key-effective", admitted);
        assertEquals(AdmissionStatus.ADMITTED, admitted.status());
    }

    @Test
    void duplicateKeyRegistrationIsRejectedAtPublish() {
        GovernanceException ex = assertThrows(GovernanceException.class,
                () -> governance.registerKey(TestFixtures.trustedKey(ARTIFACT_KEY_ID, artifactKey)));
        assertEquals(GovernanceException.Kind.KEY_CONFLICT, ex.kind());
        log.info("[duplicate-key] rejected kind={} detail={}", ex.kind(), ex.getMessage());
    }

    @Test
    void revokingUnknownKeyIsRejected() {
        GovernanceException ex = assertThrows(GovernanceException.class,
                () -> governance.revokeKey("ghost"));
        assertEquals(GovernanceException.Kind.KEY_CONFLICT, ex.kind());
        log.info("[revoke-unknown] rejected kind={} detail={}", ex.kind(), ex.getMessage());
    }

    // ---------- 策略发布阶段校验 ----------

    @Test
    void policyReferencingUntrustedKeyIsRejectedAtPublish() {
        GovernanceException ex = assertThrows(GovernanceException.class,
                () -> governance.publishPolicy(new TrustPolicy("bad-key-ref", 20, null,
                        List.of("not-a-trusted-key"), null, false)));
        assertEquals(GovernanceException.Kind.POLICY_KEY_UNTRUSTED, ex.kind());
        // 非法策略未进入生效集合
        assertFalse(policyEngine.snapshot().stream().anyMatch(p -> p.policyId().equals("bad-key-ref")));
        log.info("[publish-untrusted-key] rejected kind={} detail={}", ex.kind(), ex.getMessage());
    }

    @Test
    void contradictorySamePriorityPoliciesAreRejectedAtPublish() {
        governance.publishPolicy(new TrustPolicy("wide-a", 30, "com\\.example\\..*",
                List.of(ARTIFACT_KEY_ID), null, false));
        GovernanceException ex = assertThrows(GovernanceException.class,
                () -> governance.publishPolicy(new TrustPolicy("wide-b", 30, "com\\.example\\..*",
                        List.of(ARTIFACT_KEY_ID), null, false)));
        assertEquals(GovernanceException.Kind.POLICY_INVALID, ex.kind());
        log.info("[publish-contradiction] rejected kind={} detail={}", ex.kind(), ex.getMessage());
    }

    @Test
    void policyWithUncompilableRegexIsRejectedAtPublish() {
        GovernanceException ex = assertThrows(GovernanceException.class,
                () -> governance.publishPolicy(new TrustPolicy("bad-regex", 40, "[unterminated",
                        List.of(ARTIFACT_KEY_ID), null, false)));
        assertEquals(GovernanceException.Kind.POLICY_INVALID, ex.kind());
        log.info("[publish-bad-regex] rejected kind={} detail={}", ex.kind(), ex.getMessage());
    }

    @Test
    void duplicatePolicyIdIsRejectedAtPublish() {
        GovernanceException ex = assertThrows(GovernanceException.class,
                () -> governance.publishPolicy(new TrustPolicy("default-policy", 50, null,
                        List.of(ARTIFACT_KEY_ID), null, false)));
        assertEquals(GovernanceException.Kind.POLICY_CONFLICT, ex.kind());
        log.info("[publish-duplicate-id] rejected kind={} detail={}", ex.kind(), ex.getMessage());
    }

    @Test
    void replacingNonexistentPolicyIsRejected() {
        GovernanceException ex = assertThrows(GovernanceException.class,
                () -> governance.replacePolicy(new TrustPolicy("nope", 1, null,
                        List.of(ARTIFACT_KEY_ID), null, false)));
        assertEquals(GovernanceException.Kind.POLICY_CONFLICT, ex.kind());
        log.info("[replace-missing] rejected kind={} detail={}", ex.kind(), ex.getMessage());
    }

    @Test
    void higherPriorityPolicyPublishedChangesDecisionImmediately() {
        AdmissionRequest request = validRequest();
        AdmissionRecord first = service.submit(request);
        assertEquals(AdmissionStatus.ADMITTED, first.status());

        // 发布更高优先级（数值更小）的禁止策略（空 builder 列表显式禁止一切）并下线旧策略影响
        governance.publishPolicy(new TrustPolicy("stricter", 5, "com\\.example\\..*",
                List.of(ARTIFACT_KEY_ID), List.of(), true));
        AdmissionRecord second = service.submit(request);
        logDecision("higher-priority-policy", second);
        assertEquals(RejectReason.BUILDER_NOT_ALLOWED, second.decision().reason());
        assertNotEquals(first.recordId(), second.recordId());
    }

    @Test
    void retiringOnlyMatchingPolicyFailsClosed() {
        AdmissionRequest request = validRequest();
        assertEquals(AdmissionStatus.ADMITTED, service.submit(request).status());
        governance.retirePolicy("default-policy");
        AdmissionRecord after = service.submit(request);
        logDecision("policy-retired-fail-closed", after);
        assertEquals(RejectReason.POLICY_MISSING, after.decision().reason());
    }

    // ---------- 结论复核：信任/策略变化后重新判定 ----------

    @Test
    void previouslyAdmittedIsRejectedAfterKeyRevocation() {
        AdmissionRequest request = validRequest();
        AdmissionRecord admitted = service.submit(request);
        logDecision("admitted-before-revoke", admitted);
        assertEquals(AdmissionStatus.ADMITTED, admitted.status());

        governance.revokeKey(ARTIFACT_KEY_ID);
        AdmissionRecord rechecked = service.submit(request);
        logDecision("rechecked-after-revoke", rechecked);
        assertEquals(RejectReason.KEY_REVOKED, rechecked.decision().reason());
        assertNotEquals(admitted.recordId(), rechecked.recordId());
        // 旧记录仍可按其自身结论追溯，未被覆盖
        assertEquals(AdmissionStatus.ADMITTED, service.query(admitted.recordId()).orElseThrow().status());
    }

    @Test
    void previouslyAdmittedIsRejectedAfterKeyExpiry() {
        AdmissionRequest request = validRequest();
        AdmissionRecord admitted = service.submit(request);
        assertEquals(AdmissionStatus.ADMITTED, admitted.status());
        governance.expireKey(PROVENANCE_KEY_ID);
        AdmissionRecord rechecked = service.submit(request);
        logDecision("rechecked-after-expire", rechecked);
        assertEquals(RejectReason.KEY_EXPIRED, rechecked.decision().reason());
        assertNotEquals(admitted.recordId(), rechecked.recordId());
    }

    @Test
    void movedProvenanceIsAttributedToOriginalRecord() {
        AdmissionRequest first = validRequest();
        AdmissionRecord origin = service.submit(first);
        logDecision("provenance-origin", origin);
        assertEquals(AdmissionStatus.ADMITTED, origin.status());

        // 把同一份证明挪到另一个制品上（内容不同 -> 摘要不同，绑定检查失败）
        AdmissionRequest other = validRequest();
        AdmissionRequest moved = new AdmissionRequest(other.artifactId(), other.declaredDigest(),
                other.contentBase64(), other.signatureBase64(), other.signerKeyId(), first.provenance());
        AdmissionRecord view = service.submit(moved);
        logDecision("provenance-moved-view", view);
        assertEquals(RejectReason.PROVENANCE_NOT_BOUND, view.decision().reason());

        // 伪造绑定到另一制品摘要后重签证明体（签名仍由受信任证明者签发）：归属原结论，不产生新记录
        AdmissionRequest third = validRequest();
        ProvenanceStatement rebound = TestFixtures.provenance(third.artifactId(), third.declaredDigest(),
                BUILDER_ID, provenanceKey, PROVENANCE_KEY_ID);
        ProvenanceStatement reused = new ProvenanceStatement(first.provenance().statementId(),
                rebound.artifactId(), rebound.artifactDigest(), BUILDER_ID,
                rebound.issuedAtEpochSeconds(), PROVENANCE_KEY_ID, rebound.signature());
        AdmissionRecord attributed = service.submit(new AdmissionRequest(third.artifactId(),
                third.declaredDigest(), third.contentBase64(), third.signatureBase64(),
                third.signerKeyId(), reused));
        logDecision("provenance-reused-attributed", attributed);
        assertEquals(RejectReason.PROVENANCE_REPLAYED, attributed.decision().reason());
        assertTrue(attributed.isAttributionView());
        assertEquals(origin.recordId(), attributed.attributedRecordId());
        // 归属视图不可作为独立记录查询
        assertTrue(service.query(attributed.recordId()).isEmpty());
    }

    @Test
    void sameArtifactResubmitAfterConfigChangeReEvaluatesNotReplay() {
        AdmissionRequest request = validRequest();
        AdmissionRecord first = service.submit(request);
        assertEquals(AdmissionStatus.ADMITTED, first.status());
        // 策略收紧（不允许该 builder），同一制品+同一证明再次提交：按新策略复核，而非按重放拒绝
        governance.replacePolicy(new TrustPolicy("default-policy", 10, "com\\.example\\..*",
                List.of(ARTIFACT_KEY_ID), List.of("other-builder"), true));
        AdmissionRecord second = service.submit(request);
        logDecision("same-artifact-recheck", second);
        assertEquals(RejectReason.BUILDER_NOT_ALLOWED, second.decision().reason());
        assertNotEquals(first.recordId(), second.recordId());
    }

    // ---------- SBOM 软件成分清单 ----------

    private AdmissionRequest sbomRequest(TrustPolicy policy, List<SbomComponent> components,
                                         KeyPair signer, String signerId,
                                         String artifactIdOverride, String digestOverride) {
        governance.replacePolicy(policy);
        AdmissionRequest base = validRequest();
        SoftwareBillOfMaterials bill = TestFixtures.sbom(
                artifactIdOverride == null ? base.artifactId() : artifactIdOverride,
                digestOverride == null ? base.declaredDigest() : digestOverride,
                components, signer, signerId);
        return TestFixtures.withSbom(base, bill);
    }

    private TrustPolicy sbomPolicy(boolean requireSbom, List<String> allowedComponents,
                                   List<String> allowedSbomSigners) {
        return new TrustPolicy("default-policy", 10, "com\\.example\\..*",
                List.of(ARTIFACT_KEY_ID), List.of(BUILDER_ID), true,
                allowedSbomSigners, allowedComponents, requireSbom);
    }

    @Test
    void requiredSbomMissingIsRejected() {
        governance.replacePolicy(sbomPolicy(true, null, null));
        AdmissionRecord record = service.submit(validRequest());
        logDecision("sbom-missing", record);
        assertEquals(RejectReason.SBOM_MISSING, record.decision().reason());
    }

    @Test
    void sbomWithWrongDigestIsRejectedAsNotBound() {
        AdmissionRequest request = sbomRequest(sbomPolicy(true, null, null),
                TestFixtures.components("log4j:2.17.1"), sbomKey, SBOM_KEY_ID,
                null, "0".repeat(64));
        AdmissionRecord record = service.submit(request);
        logDecision("sbom-digest-mismatch", record);
        assertEquals(RejectReason.SBOM_NOT_BOUND, record.decision().reason());
    }

    @Test
    void sbomWithWrongArtifactIdIsRejectedAsNotBound() {
        AdmissionRequest request = sbomRequest(sbomPolicy(true, null, null),
                TestFixtures.components("log4j:2.17.1"), sbomKey, SBOM_KEY_ID,
                "com.example.other", null);
        AdmissionRecord record = service.submit(request);
        logDecision("sbom-artifact-mismatch", record);
        assertEquals(RejectReason.SBOM_NOT_BOUND, record.decision().reason());
    }

    @Test
    void forgedSbomSignatureIsRejected() {
        KeyPair attacker = TestFixtures.generateKeyPair();
        AdmissionRequest request = sbomRequest(sbomPolicy(true, null, null),
                TestFixtures.components("log4j:2.17.1"), attacker, SBOM_KEY_ID, null, null);
        AdmissionRecord record = service.submit(request);
        logDecision("sbom-forged", record);
        assertEquals(RejectReason.SBOM_UNTRUSTED, record.decision().reason());
    }

    @Test
    void sbomSignerOutsidePolicyIsRejected() {
        // 策略只信任 SBOM_KEY_ID 签 SBOM，但清单由 PROVENANCE_KEY_ID 签发（该密钥在信任库中存在）
        AdmissionRequest request = sbomRequest(sbomPolicy(true, null, List.of(SBOM_KEY_ID)),
                TestFixtures.components("log4j:2.17.1"), provenanceKey, PROVENANCE_KEY_ID, null, null);
        AdmissionRecord record = service.submit(request);
        logDecision("sbom-signer-not-allowed", record);
        assertEquals(RejectReason.SBOM_UNTRUSTED, record.decision().reason());
    }

    @Test
    void componentOutsideAllowedScopeIsRejected() {
        AdmissionRequest request = sbomRequest(sbomPolicy(true, List.of("log4j:2.17.1", "guava:32.0.0"), null),
                TestFixtures.components("log4j:2.17.1", "evil-lib:9.9.9"), sbomKey, SBOM_KEY_ID, null, null);
        AdmissionRecord record = service.submit(request);
        logDecision("sbom-component-denied", record);
        assertEquals(RejectReason.SBOM_COMPONENT_NOT_ALLOWED, record.decision().reason());
    }

    @Test
    void validBoundSbomWithinScopeIsAdmitted() {
        AdmissionRequest request = sbomRequest(sbomPolicy(true,
                List.of("log4j:2.17.1", "guava:32.0.0", "slf4j"), null),
                TestFixtures.components("log4j:2.17.1", "guava:32.0.0"), sbomKey, SBOM_KEY_ID, null, null);
        AdmissionRecord record = service.submit(request);
        logDecision("sbom-admitted", record);
        assertEquals(AdmissionStatus.ADMITTED, record.status());
        assertNull(record.decision().reason());
        assertTrue(record.decision().detail().contains("sbom"));
    }

    // ---------- 并发：读写配置与判定同时进行 ----------

    @Test
    void concurrentDecisionsSeeAtomicSnapshots() throws InterruptedException {
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<Throwable> errors = new ConcurrentLinkedQueue<>();
        AtomicLong observedVersions = new AtomicLong(-1);
        List<AdmissionRecord> decisions = java.util.Collections.synchronizedList(new ArrayList<>());

        // 一半线程持续判定，一半线程持续轮换策略版本
        for (int i = 0; i < threads; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    if (idx % 2 == 0) {
                        AdmissionRecord r = service.submit(validRequest());
                        decisions.add(r);
                    } else {
                        governance.replacePolicy(new TrustPolicy("default-policy", 10, "com\\.example\\..*",
                                List.of(ARTIFACT_KEY_ID), List.of(BUILDER_ID), true));
                        ConfigurationSnapshot s = governance.currentSnapshot();
                        observedVersions.updateAndGet(prev -> Math.max(prev, s.version()));
                    }
                } catch (Throwable t) {
                    errors.add(t);
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        assertTrue(errors.isEmpty(), "concurrent errors: " + errors);
        // 每条判定结论都记录了某一具体配置版本，且同版本下结论一致（全部 ADMITTED）
        for (AdmissionRecord r : decisions) {
            assertEquals(AdmissionStatus.ADMITTED, r.status());
            assertTrue(r.configVersion() != null && !r.configVersion().isBlank());
        }
        log.info("[concurrent-snapshots] decisions={} maxConfigVersion={} allAdmitted=true",
                decisions.size(), observedVersions.get());
    }
}
