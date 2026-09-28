package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.github.highcumontoa.artifactadmissiongatejava.governance.GovernanceRegistry;
import com.github.highcumontoa.artifactadmissiongatejava.governance.GovernanceSnapshot;
import com.github.highcumontoa.artifactadmissiongatejava.governance.PolicyPublicationException;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRecord;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionStatus;
import com.github.highcumontoa.artifactadmissiongatejava.model.RejectReason;
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
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 运行期治理测试：密钥/策略的运行中管理、发布期校验拦截、改动即时生效、并发快照一致性。
 * 日志打印输入摘要、配置版本与判定依据。
 */
class GovernanceRuntimeTest {

    private static final Logger log = LoggerFactory.getLogger(GovernanceRuntimeTest.class);
    private static final String ARTIFACT_KEY_ID = "artifact-key-1";
    private static final String PROVENANCE_KEY_ID = "provenance-key-1";
    private static final String BUILDER_ID = "builder-ci";

    private KeyPair artifactKey;
    private KeyPair provenanceKey;
    private GovernanceRegistry governance;
    private AdmissionService service;

    @BeforeEach
    void setUp() {
        artifactKey = TestFixtures.generateKeyPair();
        provenanceKey = TestFixtures.generateKeyPair();
        governance = new GovernanceRegistry();
        governance.registerKey(TestFixtures.trustedKey(ARTIFACT_KEY_ID, artifactKey));
        governance.registerKey(TestFixtures.trustedKey(PROVENANCE_KEY_ID, provenanceKey));
        service = new AdmissionService(new AdmissionStore(), governance, new PolicyEngine(),
                new ProvenanceVerifier(), new ManifestVerifier(), new ReplayGuard(),
                Clock.fixed(Instant.now(), ZoneOffset.UTC), 100, 5000);
    }

    private AdmissionRequest validRequest() {
        return TestFixtures.validRequest("com.example.app", artifactKey, ARTIFACT_KEY_ID,
                provenanceKey, PROVENANCE_KEY_ID, BUILDER_ID);
    }

    private void logResult(String name, GovernanceSnapshot before, AdmissionRecord r) {
        log.info("[{}] configVersionBefore={} recordConfigVersion={} status={} reason={} digest={} basis={}",
                name, before.version(), r.decision().configVersion(), r.status(),
                r.decision().reason(), r.decision().computedDigest(), r.decision().detail());
    }

    @Test
    void policyReferencingUnknownKeyIsRejectedAtPublishTime() {
        TrustPolicy bad = new TrustPolicy("bad-ref", 10, "com\\.example\\..*",
                List.of("ghost-key"), List.of(BUILDER_ID), true);
        PolicyPublicationException ex = assertThrows(PolicyPublicationException.class,
                () -> governance.publishPolicy(bad));
        log.info("[publish-unknown-key] code={} message={}", ex.code(), ex.getMessage());
        assertEquals("POLICY_KEY_NOT_TRUSTED", ex.code());
        // 发布失败状态不变：仍无策略，请求失败关闭
        AdmissionRecord record = service.submit(validRequest());
        assertEquals(RejectReason.POLICY_MISSING, record.decision().reason());
    }

    @Test
    void selfContradictoryPolicyIsRejectedAtPublishTime() {
        // 空签名者白名单 = 禁止一切
        PolicyPublicationException e1 = assertThrows(PolicyPublicationException.class,
                () -> governance.publishPolicy(new TrustPolicy("p-empty-signers", 10, null,
                        List.of(), null, false)));
        // 强制证明却禁止所有 builder
        PolicyPublicationException e2 = assertThrows(PolicyPublicationException.class,
                () -> governance.publishPolicy(new TrustPolicy("p-empty-builders", 10, null,
                        List.of(ARTIFACT_KEY_ID), List.of(), true)));
        // 非法正则
        PolicyPublicationException e3 = assertThrows(PolicyPublicationException.class,
                () -> governance.publishPolicy(new TrustPolicy("p-bad-regex", 10, "(unclosed",
                        List.of(ARTIFACT_KEY_ID), null, false)));
        log.info("[publish-contradiction] codes={},{},{}", e1.code(), e2.code(), e3.code());
        assertEquals("POLICY_SELF_CONTRADICTION", e1.code());
        assertEquals("POLICY_SELF_CONTRADICTION", e2.code());
        assertEquals("POLICY_PATTERN_INVALID", e3.code());
        assertTrue(governance.current().policies().isEmpty());
    }

    @Test
    void duplicatePriorityOverlappingPolicyIsRejectedAtPublishTime() {
        governance.publishPolicy(new TrustPolicy("p1", 10, "com\\.example\\..*",
                List.of(ARTIFACT_KEY_ID), null, false));
        PolicyPublicationException ex = assertThrows(PolicyPublicationException.class,
                () -> governance.publishPolicy(new TrustPolicy("p2", 10, "com\\.example\\..*",
                        List.of(ARTIFACT_KEY_ID), null, false)));
        log.info("[publish-conflict] code={} message={}", ex.code(), ex.getMessage());
        assertEquals("POLICY_CONFLICT_AT_PUBLISH", ex.code());
        assertEquals(1, governance.current().policies().size());
    }

    @Test
    void publishedPolicyTakesEffectImmediatelyWithoutRestart() {
        // 发布前：无策略，失败关闭
        GovernanceSnapshot v0 = governance.current();
        AdmissionRecord before = service.submit(validRequest());
        logResult("before-publish", v0, before);
        assertEquals(RejectReason.POLICY_MISSING, before.decision().reason());

        governance.publishPolicy(new TrustPolicy("default-policy", 10, "com\\.example\\..*",
                List.of(ARTIFACT_KEY_ID), List.of(BUILDER_ID), true));
        // 发布后：同一请求立刻按新配置判定（此处是新请求内容，因为每次 content 随机）
        AdmissionRequest req = validRequest();
        AdmissionRecord after = service.submit(req);
        logResult("after-publish", governance.current(), after);
        assertEquals(AdmissionStatus.ADMITTED, after.status());
        assertTrue(after.decision().configVersion() >= 1);

        // 下线策略：之后的请求立刻回到失败关闭
        governance.retirePolicy("default-policy");
        AdmissionRecord afterRetire = service.submit(validRequest());
        logResult("after-retire", governance.current(), afterRetire);
        assertEquals(RejectReason.POLICY_MISSING, afterRetire.decision().reason());
    }

    @Test
    void replacingPolicyWithSameIdIsAnAtomicReplacement() {
        governance.publishPolicy(new TrustPolicy("p", 10, "com\\.example\\..*",
                List.of(ARTIFACT_KEY_ID), List.of(BUILDER_ID), true));
        // 替换为禁止该签名者的版本（换白名单到另一把已注册密钥）
        KeyPair other = TestFixtures.generateKeyPair();
        governance.registerKey(TestFixtures.trustedKey("other-key", other));
        governance.publishPolicy(new TrustPolicy("p", 5, "com\\.example\\..*",
                List.of("other-key"), List.of(BUILDER_ID), true));
        AdmissionRecord r = service.submit(validRequest());
        logResult("policy-replaced", governance.current(), r);
        assertEquals(RejectReason.SIGNER_NOT_ALLOWED, r.decision().reason());
        assertEquals("p", r.decision().policyId());
    }

    @Test
    void failedPublicationLeavesStateUntouched() {
        governance.publishPolicy(new TrustPolicy("good", 10, "com\\.example\\..*",
                List.of(ARTIFACT_KEY_ID), null, false));
        long versionBefore = governance.current().version();
        assertThrows(PolicyPublicationException.class, () -> governance.publishPolicy(
                new TrustPolicy("bad", 10, "com\\.example\\..*", List.of("ghost"), null, false)));
        assertEquals(versionBefore, governance.current().version(), "failed publish must not bump version");
        assertEquals(1, governance.current().policies().size());
    }

    @Test
    void concurrentWritesAndReadsSeeWholeSnapshotsOnly() throws InterruptedException {
        int writers = 4;
        int readersPerWave = 12;
        ExecutorService pool = Executors.newFixedThreadPool(writers + readersPerWave);
        CyclicBarrier barrier = new CyclicBarrier(writers + readersPerWave);
        ConcurrentLinkedQueue<Throwable> errors = new ConcurrentLinkedQueue<>();
        AtomicInteger maxPoliciesObserved = new AtomicInteger();

        // 4 个写者持续注册新密钥+发布新策略；读者全程只能看到“密钥与策略同属一版”的完整快照
        for (int w = 0; w < writers; w++) {
            final int idx = w;
            pool.submit(() -> {
                try {
                    barrier.await();
                    for (int i = 0; i < 25; i++) {
                        KeyPair kp = TestFixtures.generateKeyPair();
                        String keyId = "dyn-key-" + idx + "-" + i;
                        governance.registerKey(TestFixtures.trustedKey(keyId, kp));
                        governance.publishPolicy(new TrustPolicy("dyn-policy-" + idx + "-" + i, 1000 + idx * 100 + i,
                                "dyn\\." + idx + "\\." + i + "\\..*", List.of(keyId), null, false));
                    }
                } catch (Throwable t) {
                    errors.add(t);
                }
            });
        }
        CountDownLatch readersDone = new CountDownLatch(readersPerWave);
        for (int r = 0; r < readersPerWave; r++) {
            pool.submit(() -> {
                try {
                    barrier.await();
                    for (int i = 0; i < 100; i++) {
                        GovernanceSnapshot snap = governance.current();
                        // 不变量：快照内每条策略引用的密钥，在同一快照里必须都存在
                        snap.policies().forEach(p -> {
                            if (p.allowedSignerKeyIds() != null) {
                                p.allowedSignerKeyIds().forEach(kid ->
                                        assertTrue(snap.keys().containsKey(kid),
                                                "torn snapshot: policy " + p.policyId()
                                                        + " references missing key " + kid + " at version "
                                                        + snap.version()));
                            }
                        });
                        maxPoliciesObserved.updateAndGet(v -> Math.max(v, snap.policies().size()));
                    }
                } catch (Throwable t) {
                    errors.add(t);
                } finally {
                    readersDone.countDown();
                }
            });
        }
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        assertTrue(errors.isEmpty(), "concurrent governance errors: " + errors);
        assertTrue(readersDone.getCount() == 0);
        log.info("[governance-concurrency] finalVersion={} maxPoliciesObserved={}",
                governance.current().version(), maxPoliciesObserved.get());
        assertEquals(writers * 25, governance.current().policies().size());
    }
}
