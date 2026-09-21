package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.github.highcumontoa.artifactadmissiongatejava.api.AdmissionResponse;
import com.github.highcumontoa.artifactadmissiongatejava.core.TimeSource;
import com.github.highcumontoa.artifactadmissiongatejava.core.admission.AdmissionException;
import com.github.highcumontoa.artifactadmissiongatejava.core.admission.AdmissionService;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.ConstraintType;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.Effect;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyRule;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.TrustPolicy;
import com.github.highcumontoa.artifactadmissiongatejava.domain.AdmissionStatus;
import com.github.highcumontoa.artifactadmissiongatejava.domain.RejectReason;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** 策略优先级组合、默认拒绝、策略冲突失败关闭。 */
class PolicyEvaluationTest extends BaseAdmissionTest {

    @Autowired
    private AdmissionService admissionService;
    @Autowired
    private TimeSource timeSource;

    private TestFixtures.KeyMaterial key;

    @BeforeEach
    void setup() {
        key = registerDefaultKey(TestFixtures.generateRsaKey());
    }

    private TestFixtures.Bundle bundleWith(String source, String artifactId, String stmt) {
        return TestFixtures.writeSignedBundle(tempDir, key, "p-" + stmt,
                source, artifactId, timeSource.now().minusSeconds(10), null, stmt,
                crypto, envelopes, attestations);
    }

    private PolicyRule rule(String id, ConstraintType c, String v, Effect e, int p) {
        return new PolicyRule(id, c, v, e, p);
    }

    @Test
    void higherPrecedenceDenyOverridesLowerAllow() {
        // signer 允许(100)，但 BUILD_SOURCE 上低优先级 ALLOW(10) 被高优先级 DENY(200) 覆盖
        policyRepository.put(new TrustPolicy("p-precedence", List.of(
                rule("s-allow", ConstraintType.SIGNER, DEFAULT_KEY, Effect.ALLOW, 100),
                rule("src-allow", ConstraintType.BUILD_SOURCE, BUILD_SOURCE, Effect.ALLOW, 10),
                rule("src-deny", ConstraintType.BUILD_SOURCE, BUILD_SOURCE, Effect.DENY, 200),
                rule("a-allow", ConstraintType.ARTIFACT_ID, ARTIFACT_ID, Effect.ALLOW, 100)
        )));
        TestFixtures.Bundle b = bundleWith(BUILD_SOURCE, ARTIFACT_ID, "stmt-precedence");
        AdmissionResponse r = admissionService.submit(b.requestNoSbom("p-precedence"));
        log.info("[policy] precedence override -> {}/{} basis={}", r.status(), r.rejectReason(), r.auditTrail());
        assertEquals(AdmissionStatus.REJECTED, r.status());
        assertEquals(RejectReason.POLICY_DENIED, r.rejectReason());
    }

    @Test
    void conflictingRulesAtSamePrecedenceRejectedAtConfigurationTime() {
        TrustPolicy conflicting = new TrustPolicy("p-conflict", List.of(
                rule("s-allow", ConstraintType.SIGNER, DEFAULT_KEY, Effect.ALLOW, 100),
                rule("s-deny", ConstraintType.SIGNER, DEFAULT_KEY, Effect.DENY, 100),
                rule("src-allow", ConstraintType.BUILD_SOURCE, BUILD_SOURCE, Effect.ALLOW, 100),
                rule("a-allow", ConstraintType.ARTIFACT_ID, ARTIFACT_ID, Effect.ALLOW, 100)
        ));
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> policyRepository.put(conflicting));
        log.info("[policy] conflict rejected reason={}", ex.getReason());
        assertEquals(RejectReason.POLICY_CONFLICT, ex.getReason());
        // 冲突策略不得发布
        assertNull(policyRepository.get("p-conflict"));
    }

    @Test
    void nonConflictingSamePrecedenceAcrossValuesIsAllowed() {
        policyRepository.put(new TrustPolicy("p-multi", List.of(
                rule("s", ConstraintType.SIGNER, DEFAULT_KEY, Effect.ALLOW, 100),
                rule("src-a", ConstraintType.BUILD_SOURCE, "ci://one", Effect.ALLOW, 100),
                rule("src-b", ConstraintType.BUILD_SOURCE, "ci://two", Effect.ALLOW, 100),
                rule("art", ConstraintType.ARTIFACT_ID, ARTIFACT_ID, Effect.ALLOW, 100)
        )));
        TestFixtures.Bundle b = bundleWith("ci://two", ARTIFACT_ID, "stmt-multi");
        AdmissionResponse r = admissionService.submit(b.requestNoSbom("p-multi"));
        assertEquals(AdmissionStatus.ADMITTED, r.status());
    }

    @Test
    void noMatchingRuleFailsClosedAsPolicyDenied() {
        // 策略里只允许另一个构建来源
        policyRepository.put(new TrustPolicy("p-nomatch", List.of(
                rule("s", ConstraintType.SIGNER, DEFAULT_KEY, Effect.ALLOW, 100),
                rule("src", ConstraintType.BUILD_SOURCE, "ci://other", Effect.ALLOW, 100),
                rule("art", ConstraintType.ARTIFACT_ID, ARTIFACT_ID, Effect.ALLOW, 100)
        )));
        TestFixtures.Bundle b = bundleWith(BUILD_SOURCE, ARTIFACT_ID, "stmt-nomatch");
        AdmissionResponse r = admissionService.submit(b.requestNoSbom("p-nomatch"));
        log.info("[policy] no-match -> {}/{} basis={}", r.status(), r.rejectReason(), r.auditTrail());
        assertEquals(AdmissionStatus.REJECTED, r.status());
        assertEquals(RejectReason.POLICY_DENIED, r.rejectReason());
    }

    @Test
    void emptyPolicyFailsClosedAtConfiguration() {
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> policyRepository.put(new TrustPolicy("p-empty", List.of())));
        assertEquals(RejectReason.POLICY_MISSING, ex.getReason());
    }

    @Test
    void explicitDenyOnArtifactIdIsRejected() {
        policyRepository.put(new TrustPolicy("p-deny-art", List.of(
                rule("s", ConstraintType.SIGNER, DEFAULT_KEY, Effect.ALLOW, 100),
                rule("src", ConstraintType.BUILD_SOURCE, BUILD_SOURCE, Effect.ALLOW, 100),
                rule("art-deny", ConstraintType.ARTIFACT_ID, ARTIFACT_ID, Effect.DENY, 500)
        )));
        TestFixtures.Bundle b = bundleWith(BUILD_SOURCE, ARTIFACT_ID, "stmt-deny-art");
        AdmissionResponse r = admissionService.submit(b.requestNoSbom("p-deny-art"));
        assertEquals(AdmissionStatus.REJECTED, r.status());
        assertEquals(RejectReason.POLICY_DENIED, r.rejectReason());
    }
}
