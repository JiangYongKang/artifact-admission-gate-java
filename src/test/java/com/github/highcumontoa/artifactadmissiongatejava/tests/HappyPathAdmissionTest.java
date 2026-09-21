package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.github.highcumontoa.artifactadmissiongatejava.api.AdmissionResponse;
import com.github.highcumontoa.artifactadmissiongatejava.core.TimeSource;
import com.github.highcumontoa.artifactadmissiongatejava.core.admission.AdmissionService;
import com.github.highcumontoa.artifactadmissiongatejava.domain.AdmissionStatus;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/** 正常路径：完整绑定的制品/签名/证明/SBOM 应被放行，且可查询到一致结论。 */
class HappyPathAdmissionTest extends BaseAdmissionTest {

    @Autowired
    private AdmissionService admissionService;
    @Autowired
    private TimeSource timeSource;

    @Test
    void admitsFullySignedArtifactWithProvenanceAndSbom() {
        TestFixtures.KeyMaterial key = registerDefaultKey(TestFixtures.generateRsaKey());
        configureAllowAllPolicy();
        Instant signedAt = timeSource.now().minusSeconds(60);

        TestFixtures.Bundle bundle = TestFixtures.writeSignedBundle(
                tempDir, key, "artifact-bytes-v1", BUILD_SOURCE, ARTIFACT_ID,
                signedAt, "{\"components\":[]}", crypto, envelopes, attestations);

        log.info("[happy] input digest={} statement={}", bundle.digest(), bundle.statementId());
        AdmissionResponse response = admissionService.submit(bundle.request(POLICY));

        log.info("[happy] decision status={} reason={} basis={}",
                response.status(), response.rejectReason(), response.auditTrail());
        assertEquals(AdmissionStatus.ADMITTED, response.status());
        assertNull(response.rejectReason());
        assertEquals(bundle.digest(), response.artifactDigest());
        assertEquals(DEFAULT_KEY, response.signerKeyId());
        assertFalse(response.replay());

        AdmissionResponse queried = admissionService.query(response.admissionId());
        assertEquals(response.status(), queried.status());
        assertEquals(response.rejectReason(), queried.rejectReason());
        assertEquals(response.artifactDigest(), queried.artifactDigest());
    }

    @Test
    void admitsWithoutSbomWhenNotSubmitted() {
        TestFixtures.KeyMaterial key = registerDefaultKey(TestFixtures.generateRsaKey());
        configureAllowAllPolicy();
        TestFixtures.Bundle bundle = TestFixtures.writeSignedBundle(
                tempDir, key, "artifact-bytes-v2", BUILD_SOURCE, ARTIFACT_ID,
                timeSource.now().minusSeconds(10), null, crypto, envelopes, attestations);

        AdmissionResponse response = admissionService.submit(bundle.requestNoSbom(POLICY));
        log.info("[happy-no-sbom] digest={} decision={}/{}", bundle.digest(),
                response.status(), response.rejectReason());
        assertEquals(AdmissionStatus.ADMITTED, response.status());
    }
}
