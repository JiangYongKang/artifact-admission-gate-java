package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.github.highcumontoa.artifactadmissiongatejava.api.AdmissionResponse;
import com.github.highcumontoa.artifactadmissiongatejava.core.TimeSource;
import com.github.highcumontoa.artifactadmissiongatejava.core.admission.AdmissionService;
import com.github.highcumontoa.artifactadmissiongatejava.domain.AdmissionStatus;
import com.github.highcumontoa.artifactadmissiongatejava.domain.KeyState;
import com.github.highcumontoa.artifactadmissiongatejava.domain.RejectReason;
import com.github.highcumontoa.artifactadmissiongatejava.core.trust.TrustedKey;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 信任根生命周期：轮换、撤销、过期。
 * 用固定时钟保证“轮换前/轮换后签名”“过期前/过期后判定”可确定性复现。
 */
class KeyLifecycleTest extends BaseAdmissionTest {

    @Autowired
    private AdmissionService admissionService;
    @Autowired
    private TimeSource timeSource;

    private static final Instant T0 = Instant.parse("2026-09-01T00:00:00Z");
    private static final Instant ROTATED_AT = Instant.parse("2026-09-10T00:00:00Z");
    private static final Instant EXPIRES_AT = Instant.parse("2026-09-20T00:00:00Z");

    private void clockAt(Instant t) {
        timeSource.setClock(Clock.fixed(t, ZoneOffset.UTC));
    }

    private TestFixtures.KeyMaterial key(String id) {
        TestFixtures.KeyMaterial material = TestFixtures.writeKey(tempDir, id, TestFixtures.generateRsaKey(), crypto);
        trustStore.register(new TrustedKey(id, material.keyPair().getPublic(),
                KeyState.ACTIVE, null, null, null));
        return material;
    }

    private TestFixtures.Bundle bundle(TestFixtures.KeyMaterial km, Instant signedAt, String stmt) {
        return TestFixtures.writeSignedBundle(tempDir, km, "life-" + stmt,
                BUILD_SOURCE, ARTIFACT_ID, signedAt, null, stmt,
                crypto, envelopes, attestations);
    }

    @Test
    void oldSignatureBeforeRotationRemainsValidAfterRotation() {
        clockAt(T0);
        TestFixtures.KeyMaterial oldKey = key("old-root");
        configureAllowAllPolicyFor("old-root");
        TestFixtures.Bundle old = bundle(oldKey, T0.plusSeconds(60), "stmt-rotate-old");

        TestFixtures.KeyMaterial newKey = key("new-root");
        clockAt(ROTATED_AT);
        trustStore.rotate("old-root", "new-root", ROTATED_AT);

        AdmissionResponse response = admissionService.submit(old.requestNoSbom(policyFor("old-root")));
        log.info("[rotate] old-signature signedBeforeRotation -> {}/{} digest={}",
                response.status(), response.rejectReason(), response.artifactDigest());
        assertEquals(AdmissionStatus.ADMITTED, response.status());
    }

    @Test
    void signatureAfterRotationByOldKeyIsSuperseded() {
        clockAt(T0);
        TestFixtures.KeyMaterial oldKey = key("old-root-2");
        configureAllowAllPolicyFor("old-root-2");
        TestFixtures.KeyMaterial newKey = key("new-root-2");
        trustStore.rotate("old-root-2", "new-root-2", ROTATED_AT);

        clockAt(ROTATED_AT.plusSeconds(3600));
        // 轮换后仍用旧根签发
        TestFixtures.Bundle late = bundle(oldKey, ROTATED_AT.plusSeconds(60), "stmt-rotate-late");
        AdmissionResponse response = admissionService.submit(late.requestNoSbom(policyFor("old-root-2")));
        log.info("[rotate] signature-after-rotation -> {}/{}", response.status(), response.rejectReason());
        assertEquals(AdmissionStatus.REJECTED, response.status());
        assertEquals(RejectReason.KEY_SUPERSEDED, response.rejectReason());
    }

    @Test
    void revokedKeyNeverPassesEvenForOldSignatures() {
        clockAt(T0);
        TestFixtures.KeyMaterial k = key("revoked-root");
        configureAllowAllPolicyFor("revoked-root");
        TestFixtures.Bundle old = bundle(k, T0.plusSeconds(60), "stmt-revoke-old");

        clockAt(ROTATED_AT);
        trustStore.revoke("revoked-root", ROTATED_AT);
        AdmissionResponse response = admissionService.submit(old.requestNoSbom(policyFor("revoked-root")));
        log.info("[revoke] historical-signature after revoke -> {}/{}", response.status(), response.rejectReason());
        assertEquals(AdmissionStatus.REJECTED, response.status());
        assertEquals(RejectReason.KEY_REVOKED, response.rejectReason());
    }

    @Test
    void expiredKeyIsRejectedAsExpired() {
        clockAt(T0);
        TestFixtures.KeyMaterial material = TestFixtures.writeKey(tempDir, "expiring-root",
                TestFixtures.generateRsaKey(), crypto);
        trustStore.register(new TrustedKey("expiring-root", material.keyPair().getPublic(),
                KeyState.ACTIVE, EXPIRES_AT, null, null));
        configureAllowAllPolicyFor("expiring-root");
        TestFixtures.Bundle old = bundle(material, T0.plusSeconds(60), "stmt-expired");

        clockAt(EXPIRES_AT.plusSeconds(1));
        AdmissionResponse response = admissionService.submit(old.requestNoSbom(policyFor("expiring-root")));
        log.info("[expire] at={} -> {}/{}", EXPIRES_AT.plusSeconds(1),
                response.status(), response.rejectReason());
        assertEquals(AdmissionStatus.REJECTED, response.status());
        assertEquals(RejectReason.KEY_EXPIRED, response.rejectReason());
    }

    @Test
    void keyStillValidJustBeforeExpiry() {
        clockAt(EXPIRES_AT.minusSeconds(60));
        TestFixtures.KeyMaterial material = TestFixtures.writeKey(tempDir, "not-yet-expired",
                TestFixtures.generateRsaKey(), crypto);
        trustStore.register(new TrustedKey("not-yet-expired", material.keyPair().getPublic(),
                KeyState.ACTIVE, EXPIRES_AT, null, null));
        configureAllowAllPolicyFor("not-yet-expired");
        TestFixtures.Bundle b = bundle(material, EXPIRES_AT.minusSeconds(120), "stmt-before-expiry");
        AdmissionResponse response = admissionService.submit(b.requestNoSbom(policyFor("not-yet-expired")));
        assertEquals(AdmissionStatus.ADMITTED, response.status());
    }

    private void configureAllowAllPolicyFor(String signer) {
        policyRepository.put(new com.github.highcumontoa.artifactadmissiongatejava.core.policy.TrustPolicy(
                policyFor(signer), java.util.List.of(
                new com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyRule(
                        "s", com.github.highcumontoa.artifactadmissiongatejava.core.policy.ConstraintType.SIGNER,
                        signer, com.github.highcumontoa.artifactadmissiongatejava.core.policy.Effect.ALLOW, 100),
                new com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyRule(
                        "b", com.github.highcumontoa.artifactadmissiongatejava.core.policy.ConstraintType.BUILD_SOURCE,
                        BUILD_SOURCE, com.github.highcumontoa.artifactadmissiongatejava.core.policy.Effect.ALLOW, 100),
                new com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyRule(
                        "a", com.github.highcumontoa.artifactadmissiongatejava.core.policy.ConstraintType.ARTIFACT_ID,
                        ARTIFACT_ID, com.github.highcumontoa.artifactadmissiongatejava.core.policy.Effect.ALLOW, 100))));
    }

    private String policyFor(String signer) {
        return "policy-for-" + signer;
    }
}
