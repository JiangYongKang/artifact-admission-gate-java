package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.github.highcumontoa.artifactadmissiongatejava.api.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.api.AdmissionResponse;
import com.github.highcumontoa.artifactadmissiongatejava.core.TimeSource;
import com.github.highcumontoa.artifactadmissiongatejava.core.admission.AdmissionService;
import com.github.highcumontoa.artifactadmissiongatejava.domain.AdmissionStatus;
import com.github.highcumontoa.artifactadmissiongatejava.domain.RejectReason;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/** 异常输入：每类失败都必须被拒绝，且原因码可区分。 */
class NegativeInputTest extends BaseAdmissionTest {

    @Autowired
    private AdmissionService admissionService;
    @Autowired
    private TimeSource timeSource;

    private TestFixtures.KeyMaterial key;

    private TestFixtures.KeyMaterial key() {
        if (key == null) {
            // 整个测试类共用一把受信密钥与一份策略，避免同 keyId 重复注册不同公钥
            key = registerDefaultKey(TestFixtures.generateRsaKey());
            configureAllowAllPolicy();
        }
        return key;
    }

    private TestFixtures.Bundle validBundle(String suffix) {
        return TestFixtures.writeSignedBundle(tempDir, key(), "content-" + suffix,
                BUILD_SOURCE, ARTIFACT_ID, timeSource.now().minusSeconds(30),
                "{\"v\":1}", "stmt-" + suffix + "-" + System.nanoTime(),
                crypto, envelopes, attestations);
    }

    private void assertRejected(TestFixtures.Bundle bundle, RejectReason expected, boolean withSbom) {
        AdmissionRequest req = withSbom ? bundle.request(POLICY) : bundle.requestNoSbom(POLICY);
        AdmissionResponse response = admissionService.submit(req);
        log.info("[negative] expected={} actual={}/{} digest={} basis={}",
                expected, response.status(), response.rejectReason(),
                response.artifactDigest(), response.auditTrail());
        assertEquals(AdmissionStatus.REJECTED, response.status());
        assertEquals(expected, response.rejectReason());
    }

    @Test
    void forgedSignatureByUnknownKeyIsRejectedAsUntrusted() {
        TestFixtures.Bundle bundle = validBundle("forged");
        TestFixtures.KeyMaterial attacker = TestFixtures.writeKey(
                tempDir, "attacker-forged", TestFixtures.generateRsaKey(), crypto);
        // 攻击者密钥未登记进信任根
        TestFixtures.resignArtifactWith(bundle, attacker, timeSource.now(), crypto, envelopes);
        assertRejected(bundle, RejectReason.KEY_UNTRUSTED, true);
    }

    @Test
    void tamperedArtifactIsRejectedAsDigestMismatch() {
        TestFixtures.Bundle bundle = validBundle("tampered");
        TestFixtures.tamperArtifact(bundle);
        assertRejected(bundle, RejectReason.DIGEST_MISMATCH, true);
    }

    @Test
    void missingAttestationIsRejected() {
        TestFixtures.Bundle bundle = validBundle("noatt");
        AdmissionRequest req = new AdmissionRequest(
                bundle.artifact().toString(), bundle.digest(), bundle.signature().toString(),
                tempDir.resolve("does-not-exist.json").toString(), null, POLICY);
        AdmissionResponse response = admissionService.submit(req);
        log.info("[negative] attestation-missing -> {}/{}", response.status(), response.rejectReason());
        assertEquals(AdmissionStatus.REJECTED, response.status());
        assertEquals(RejectReason.ATTESTATION_MISSING, response.rejectReason());
    }

    @Test
    void attestationBoundToAnotherDigestIsRejectedAsNotBound() {
        TestFixtures.Bundle bundle = validBundle("unbound");
        TestFixtures.rebindAttestationDigest(bundle,
                "0000000000000000000000000000000000000000000000000000000000000000", attestations);
        assertRejected(bundle, RejectReason.ATTESTATION_NOT_BOUND, true);
    }

    @Test
    void malformedAttestationIsRejectedAsMalformed() {
        TestFixtures.Bundle bundle = validBundle("malformed");
        TestFixtures.corruptAttestationFile(bundle);
        assertRejected(bundle, RejectReason.ATTESTATION_MALFORMED, true);
    }

    @Test
    void corruptedSignatureEnvelopeIsRejectedAsSignatureInvalid() {
        TestFixtures.Bundle bundle = validBundle("badsig");
        TestFixtures.corruptSignatureFile(bundle);
        assertRejected(bundle, RejectReason.SIGNATURE_INVALID, true);
    }

    @Test
    void attestationSignedByUntrustedKeyIsRejectedAsSignatureUntrusted() {
        TestFixtures.Bundle bundle = validBundle("att-forged");
        TestFixtures.KeyMaterial attacker = TestFixtures.writeKey(
                tempDir, "attacker-att", TestFixtures.generateRsaKey(), crypto);
        TestFixtures.reSignAttestationWithWrongKey(bundle, attacker, crypto, attestations);
        // 制品签名有效且 key 受信；证明签名来自未登记密钥 -> KEY_UNTRUSTED
        assertRejected(bundle, RejectReason.KEY_UNTRUSTED, true);
    }

    @Test
    void sbomTamperedAfterAttestationIsRejectedAsSbomMismatch() {
        TestFixtures.Bundle bundle = validBundle("sbom");
        TestFixtures.tamperSbom(bundle, "{\"components\":[{\"name\":\"evil\"}]}");
        assertRejected(bundle, RejectReason.SBOM_DIGEST_MISMATCH, true);
    }

    @Test
    void unknownPolicyFailsClosed() {
        TestFixtures.Bundle bundle = validBundle("nopolicy");
        AdmissionRequest req = bundle.request("no-such-policy");
        AdmissionResponse response = admissionService.submit(req);
        log.info("[negative] unknown-policy -> {}/{}", response.status(), response.rejectReason());
        assertEquals(AdmissionStatus.REJECTED, response.status());
        assertEquals(RejectReason.POLICY_MISSING, response.rejectReason());
    }

    @Test
    void invalidRequestShapeRejectedAsBadRequest() {
        AdmissionRequest bad = new AdmissionRequest(null, null, null, null, null, POLICY);
        var ex = assertThrows(com.github.highcumontoa.artifactadmissiongatejava.core.admission.AdmissionException.class,
                () -> admissionService.submit(bad));
        assertEquals(RejectReason.BAD_REQUEST, ex.getReason());
    }
}
