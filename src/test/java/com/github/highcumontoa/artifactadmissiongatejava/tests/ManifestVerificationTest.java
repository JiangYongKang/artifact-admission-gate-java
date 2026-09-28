package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.github.highcumontoa.artifactadmissiongatejava.governance.GovernanceRegistry;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRecord;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionStatus;
import com.github.highcumontoa.artifactadmissiongatejava.model.ComponentManifest;
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

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 软件成分清单（SBOM）校验测试：缺失、未绑定（制品标识/摘要对不上）、组件越权三类原因各自可区分；
 * 绑定正确且组件在允许范围内才放行。日志打印输入摘要与判定依据。
 */
class ManifestVerificationTest {

    private static final Logger log = LoggerFactory.getLogger(ManifestVerificationTest.class);
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

    /** 发布要求清单的策略：组件只允许 com.acme.* 与 lib-safe。 */
    private void useManifestRequiredPolicy() {
        governance.seedPolicies(List.of(new TrustPolicy("sbom-policy", 10, "com\\.example\\..*",
                List.of(ARTIFACT_KEY_ID), List.of(BUILDER_ID), true, true,
                List.of("com\\.acme\\..*", "lib-safe"))));
    }

    private AdmissionRequest validBase() {
        return TestFixtures.validRequest("com.example.app", artifactKey, ARTIFACT_KEY_ID,
                provenanceKey, PROVENANCE_KEY_ID, BUILDER_ID);
    }

    private AdmissionRequest withManifest(AdmissionRequest base, ComponentManifest manifest) {
        return new AdmissionRequest(base.artifactId(), base.declaredDigest(), base.contentBase64(),
                base.signatureBase64(), base.signerKeyId(), base.provenance(), manifest);
    }

    private ComponentManifest boundManifest(AdmissionRequest base, ComponentManifest.Component... components) {
        return TestFixtures.manifest(base.artifactId(), base.declaredDigest(), List.of(components));
    }

    private void logResult(String name, AdmissionRecord r) {
        log.info("[{}] status={} reason={} digest={} basis={}", name, r.status(),
                r.decision().reason(), r.decision().computedDigest(), r.decision().detail());
    }

    @Test
    void missingManifestIsRejectedWhenRequired() {
        useManifestRequiredPolicy();
        AdmissionRecord r = service.submit(validBase());
        logResult("sbom-missing", r);
        assertEquals(RejectReason.SBOM_MISSING, r.decision().reason());
    }

    @Test
    void boundManifestWithAllowedComponentsIsAdmitted() {
        useManifestRequiredPolicy();
        AdmissionRequest base = validBase();
        AdmissionRequest req = withManifest(base, boundManifest(base,
                TestFixtures.component("com.acme.logging", "1.2.3"),
                TestFixtures.component("lib-safe", "4.0")));
        AdmissionRecord r = service.submit(req);
        logResult("sbom-valid", r);
        assertEquals(AdmissionStatus.ADMITTED, r.status());
    }

    @Test
    void manifestArtifactIdMismatchIsRejectedAsNotBound() {
        useManifestRequiredPolicy();
        AdmissionRequest base = validBase();
        ComponentManifest wrongId = new ComponentManifest("sbom-x", "com.example.someone-else",
                base.declaredDigest(), List.of(TestFixtures.component("com.acme.logging", "1.0")));
        AdmissionRecord r = service.submit(withManifest(base, wrongId));
        logResult("sbom-artifactid-mismatch", r);
        assertEquals(RejectReason.SBOM_NOT_BOUND, r.decision().reason());
    }

    @Test
    void manifestDigestMismatchIsRejectedAsNotBound() {
        useManifestRequiredPolicy();
        AdmissionRequest base = validBase();
        ComponentManifest wrongDigest = new ComponentManifest("sbom-x", base.artifactId(),
                "a".repeat(64), List.of(TestFixtures.component("com.acme.logging", "1.0")));
        AdmissionRecord r = service.submit(withManifest(base, wrongDigest));
        logResult("sbom-digest-mismatch", r);
        assertEquals(RejectReason.SBOM_NOT_BOUND, r.decision().reason());
    }

    @Test
    void componentOutsideAllowedRangeIsRejected() {
        useManifestRequiredPolicy();
        AdmissionRequest base = validBase();
        AdmissionRequest req = withManifest(base, boundManifest(base,
                TestFixtures.component("com.acme.logging", "1.0"),
                TestFixtures.component("com.malicious.backdoor", "9.9")));
        AdmissionRecord r = service.submit(req);
        logResult("sbom-component-violation", r);
        assertEquals(RejectReason.SBOM_COMPONENT_VIOLATION, r.decision().reason());
    }

    @Test
    void suppliedManifestIsStillCheckedEvenWhenNotRequired() {
        // 不强制清单，但限制组件范围：主动提供的清单若含越权组件仍要拒绝
        governance.seedPolicies(List.of(new TrustPolicy("range-policy", 10, "com\\.example\\..*",
                List.of(ARTIFACT_KEY_ID), List.of(BUILDER_ID), true, false,
                List.of("com\\.acme\\..*"))));
        AdmissionRequest base = validBase();
        AdmissionRequest req = withManifest(base, boundManifest(base,
                TestFixtures.component("com.evil.thing", "1.0")));
        AdmissionRecord r = service.submit(req);
        logResult("sbom-optional-but-violating", r);
        assertEquals(RejectReason.SBOM_COMPONENT_VIOLATION, r.decision().reason());

        // 不提供清单则不受此约束影响，正常放行
        AdmissionRecord noManifest = service.submit(validBase());
        logResult("sbom-optional-absent", noManifest);
        assertEquals(AdmissionStatus.ADMITTED, noManifest.status());
    }
}
