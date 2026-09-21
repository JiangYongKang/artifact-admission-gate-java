package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.github.highcumontoa.artifactadmissiongatejava.api.AdmissionResponse;
import com.github.highcumontoa.artifactadmissiongatejava.core.TimeSource;
import com.github.highcumontoa.artifactadmissiongatejava.core.admission.AdmissionRepository;
import com.github.highcumontoa.artifactadmissiongatejava.core.admission.AdmissionService;
import com.github.highcumontoa.artifactadmissiongatejava.domain.AdmissionStatus;
import com.github.highcumontoa.artifactadmissiongatejava.domain.RejectReason;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.junit.jupiter.api.Assertions.*;

/** 重放防护：同一证明重复提交不得产生新记录，也不得绕过撤销或拒绝结论。 */
class ReplayProtectionTest extends BaseAdmissionTest {

    @Autowired
    private AdmissionService admissionService;
    @Autowired
    private AdmissionRepository repository;
    @Autowired
    private TimeSource timeSource;

    private TestFixtures.KeyMaterial key;

    @BeforeEach
    void initKey() {
        // 类内所有方法共用一把受信密钥，避免同 keyId 重复注册不同公钥
        key = registerDefaultKey(TestFixtures.generateRsaKey());
    }

    @Test
    void duplicateAttestationDoesNotCreateNewRecordAndIncrementsReplay() {
        configureAllowAllPolicy();
        TestFixtures.Bundle bundle = TestFixtures.writeSignedBundle(
                tempDir, key, "replay-content", BUILD_SOURCE, ARTIFACT_ID,
                timeSource.now().minusSeconds(30), null, "stmt-replay-dup",
                crypto, envelopes, attestations);

        AdmissionResponse first = admissionService.submit(bundle.requestNoSbom(POLICY));
        AdmissionResponse second = admissionService.submit(bundle.requestNoSbom(POLICY));
        AdmissionResponse third = admissionService.submit(bundle.requestNoSbom(POLICY));

        log.info("[replay] firstId={} secondId={} replayFlags={},{},{} counts={},{},{} totalRecords={}",
                first.admissionId(), second.admissionId(),
                first.replay(), second.replay(), third.replay(),
                first.replayCount(), second.replayCount(), third.replayCount(),
                repository.all().size());

        assertEquals(first.admissionId(), second.admissionId());
        assertEquals(first.admissionId(), third.admissionId());
        assertFalse(first.replay());
        assertTrue(second.replay());
        assertTrue(third.replay());
        assertEquals(2, third.replayCount());
        assertEquals(1, repository.all().size());
    }

    @Test
    void replayCannotOverturnPriorRejection() {
        policyRepository.put(new com.github.highcumontoa.artifactadmissiongatejava.core.policy.TrustPolicy(
                POLICY, java.util.List.of(
                new com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyRule(
                        "s", com.github.highcumontoa.artifactadmissiongatejava.core.policy.ConstraintType.SIGNER,
                        DEFAULT_KEY, com.github.highcumontoa.artifactadmissiongatejava.core.policy.Effect.ALLOW, 100),
                new com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyRule(
                        "src", com.github.highcumontoa.artifactadmissiongatejava.core.policy.ConstraintType.BUILD_SOURCE,
                        "ci://other", com.github.highcumontoa.artifactadmissiongatejava.core.policy.Effect.ALLOW, 100),
                new com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyRule(
                        "art", com.github.highcumontoa.artifactadmissiongatejava.core.policy.ConstraintType.ARTIFACT_ID,
                        ARTIFACT_ID, com.github.highcumontoa.artifactadmissiongatejava.core.policy.Effect.ALLOW, 100))));
        TestFixtures.Bundle bundle = TestFixtures.writeSignedBundle(
                tempDir, key, "replay-denied", BUILD_SOURCE, ARTIFACT_ID,
                timeSource.now().minusSeconds(30), null, "stmt-replay-denied",
                crypto, envelopes, attestations);

        AdmissionResponse first = admissionService.submit(bundle.requestNoSbom(POLICY));
        assertEquals(AdmissionStatus.REJECTED, first.status());
        assertEquals(RejectReason.POLICY_DENIED, first.rejectReason());

        // 即使之后策略变为允许，重放也不得推翻已生效的拒绝
        configureAllowAllPolicy();
        AdmissionResponse replay = admissionService.submit(bundle.requestNoSbom(POLICY));
        log.info("[replay] prior-denial on replay -> {}/{} basis={}",
                replay.status(), replay.rejectReason(), replay.auditTrail());
        assertEquals(AdmissionStatus.REJECTED, replay.status());
        assertEquals(RejectReason.POLICY_DENIED, replay.rejectReason());
        assertEquals(first.admissionId(), replay.admissionId());
    }

    @Test
    void priorAdmissionFlipsToRejectedWhenKeyRevokedBeforeReplay() {
        configureAllowAllPolicy();
        TestFixtures.Bundle bundle = TestFixtures.writeSignedBundle(
                tempDir, key, "replay-revoke", BUILD_SOURCE, ARTIFACT_ID,
                timeSource.now().minusSeconds(30), null, "stmt-replay-revoke",
                crypto, envelopes, attestations);

        AdmissionResponse first = admissionService.submit(bundle.requestNoSbom(POLICY));
        assertEquals(AdmissionStatus.ADMITTED, first.status());

        trustStore.revoke(DEFAULT_KEY, timeSource.now());
        AdmissionResponse replay = admissionService.submit(bundle.requestNoSbom(POLICY));
        log.info("[replay] after revoke -> {}/{} totalRecords={}",
                replay.status(), replay.rejectReason(), repository.all().size());
        assertEquals(AdmissionStatus.REJECTED, replay.status());
        assertEquals(RejectReason.KEY_REVOKED, replay.rejectReason());
        assertEquals(1, repository.all().size());
    }
}
