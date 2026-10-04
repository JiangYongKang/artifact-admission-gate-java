package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.github.highcumontoa.artifactadmissiongatejava.governance.GovernanceRegistry;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 结论复核测试：信任/策略变化后，同一制品再次提交必须按最新状态重新判定；
 * 结论变化产生修订版（revision 递增、supersedesRecordId 串联），结论不变则幂等归并。
 */
class ReevaluationTest {

    private static final Logger log = LoggerFactory.getLogger(ReevaluationTest.class);
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
        service = new AdmissionService(store, governance, new PolicyEngine(),
                new ProvenanceVerifier(), new ManifestVerifier(), new ReplayGuard(),
                Clock.fixed(Instant.now(), ZoneOffset.UTC), 100, 5000);
    }

    private AdmissionRequest fixedRequest() {
        // 内容固定，保证两次提交 requestHash 完全一致（同一制品的同一请求）
        byte[] content = "fixed-artifact-content".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String digest = com.github.highcumontoa.artifactadmissiongatejava.trust.CryptoSupport.sha256Hex(content);
        String signature = TestFixtures.sign(artifactKey.getPrivate(), digest);
        var provenance = TestFixtures.provenance("com.example.app", digest, BUILDER_ID,
                provenanceKey, PROVENANCE_KEY_ID);
        return new AdmissionRequest("com.example.app", digest,
                java.util.Base64.getEncoder().encodeToString(content), signature,
                ARTIFACT_KEY_ID, provenance);
    }

    private void logChain(String name, AdmissionRecord head) {
        log.info("[{}] headRecordId={} revision={} supersedes={} status={} reason={} configVersion={} digest={}",
                name, head.recordId(), head.revision(), head.supersedesRecordId(), head.status(),
                head.decision().reason(), head.decision().configVersion(), head.decision().computedDigest());
    }

    @Test
    void revokingPreviouslyTrustedKeyFlipsAdmissionToRejected() {
        AdmissionRequest request = fixedRequest();
        AdmissionRecord v1 = service.submit(request);
        assertEquals(AdmissionStatus.ADMITTED, v1.status());
        assertEquals(1, v1.revision());
        assertNull(v1.supersedesRecordId());

        governance.revokeKey(ARTIFACT_KEY_ID);
        AdmissionRecord v2 = service.submit(request);
        logChain("key-revoked-recheck", v2);
        assertEquals(AdmissionStatus.REJECTED, v2.status());
        assertEquals(RejectReason.KEY_REVOKED, v2.decision().reason());
        assertEquals(2, v2.revision(), "changed conclusion must be a new revision");
        assertEquals(v1.recordId(), v2.supersedesRecordId(), "revision must supersede the original record");
        assertNotEquals(v1.recordId(), v2.recordId());

        // 旧记录仍可按 recordId 查询，且历史结论未被改写
        AdmissionRecord history = store.findById(v1.recordId()).orElseThrow();
        assertEquals(AdmissionStatus.ADMITTED, history.status());
        // 请求哈希指向的最新记录是 v2
        assertEquals(v2.recordId(), store.findByRequestHash(AdmissionService.hashRequest(request))
                .orElseThrow().recordId());
    }

    @Test
    void expiringKeyFlipsAdmissionToRejected() {
        AdmissionRequest request = fixedRequest();
        AdmissionRecord v1 = service.submit(request);
        assertEquals(AdmissionStatus.ADMITTED, v1.status());

        governance.expireKey(PROVENANCE_KEY_ID);
        AdmissionRecord v2 = service.submit(request);
        logChain("key-expired-recheck", v2);
        assertEquals(RejectReason.KEY_EXPIRED, v2.decision().reason());
        assertEquals(2, v2.revision());
        assertTrue(v2.decision().configVersion() > v1.decision().configVersion());
    }

    @Test
    void higherPriorityPolicyIsPickedOnResubmission() {
        AdmissionRequest request = fixedRequest();
        AdmissionRecord v1 = service.submit(request);
        assertEquals("default-policy", v1.decision().policyId());

        // 发布数值更小（优先级更高）且匹配同一制品的新策略，新策略禁止当前 builder
        governance.publishPolicy(new TrustPolicy("stricter-policy", 5, "com\\.example\\..*",
                List.of(ARTIFACT_KEY_ID), List.of("some-other-builder"), true));
        AdmissionRecord v2 = service.submit(request);
        logChain("higher-priority-recheck", v2);
        assertEquals(AdmissionStatus.REJECTED, v2.status());
        assertEquals(RejectReason.BUILDER_NOT_ALLOWED, v2.decision().reason());
        assertEquals("stricter-policy", v2.decision().policyId());
        assertEquals(2, v2.revision());
        assertEquals(v1.recordId(), v2.supersedesRecordId());
    }

    @Test
    void policyRetirementFlipsToFailClosedOnResubmission() {
        AdmissionRequest request = fixedRequest();
        AdmissionRecord v1 = service.submit(request);
        assertEquals(AdmissionStatus.ADMITTED, v1.status());

        governance.retirePolicy("default-policy");
        AdmissionRecord v2 = service.submit(request);
        logChain("policy-retired-recheck", v2);
        assertEquals(RejectReason.POLICY_MISSING, v2.decision().reason());
        assertEquals(2, v2.revision());
    }

    @Test
    void unrelatedConfigBumpKeepsSameConclusionAndRecord() {
        AdmissionRequest request = fixedRequest();
        AdmissionRecord v1 = service.submit(request);

        // 注册一把无关的新密钥、发布一份不匹配该制品的策略：配置版本递增但结论不变
        KeyPair extra = TestFixtures.generateKeyPair();
        governance.registerKey(TestFixtures.trustedKey("extra-key", extra));
        governance.publishPolicy(new TrustPolicy("unrelated-policy", 1, "org\\.other\\..*",
                List.of("extra-key"), null, false));

        AdmissionRecord again = service.submit(request);
        logChain("unrelated-change-recheck", again);
        assertEquals(AdmissionStatus.ADMITTED, again.status());
        assertEquals(v1.recordId(), again.recordId(), "unchanged conclusion must merge into the same record");
        assertEquals(1, again.revision());
    }

    @Test
    void staleAdmittedRecordIsNeverServedFromStore() {
        AdmissionRequest request = fixedRequest();
        AdmissionRecord first = service.submit(request);
        assertEquals(AdmissionStatus.ADMITTED, first.status());
        governance.revokeKey(ARTIFACT_KEY_ID);
        // 即便底层已存在旧的放行记录，重提也绝不能把旧结论端回
        AdmissionRecord second = service.submit(request);
        assertEquals(AdmissionStatus.REJECTED, second.status());
        AdmissionRecord third = service.submit(request);
        // 结论稳定为拒绝后再提：归并为同一条拒绝记录（revision 仍为 2）
        assertEquals(second.recordId(), third.recordId());
        assertEquals(2, third.revision());
        logChain("no-stale-serve", third);
    }

    @Test
    void sameOutcomeUnderNewPolicySourceYieldsNewRevisionBoundToCurrentConfig() {
        // 用户复现场景：放行后发布一份优先级更高、仍放行该制品的新策略，
        // 完全相同的输入重提，结论必须绑定最新配置（新策略来源 + 新配置版本），
        // 而不是把改动前那条记录端回来。
        AdmissionRequest request = fixedRequest();
        AdmissionRecord v1 = service.submit(request);
        assertEquals(AdmissionStatus.ADMITTED, v1.status());
        assertEquals("default-policy", v1.decision().policyId());
        long v1Config = v1.decision().configVersion();

        governance.publishPolicy(new TrustPolicy("newer-policy", 5, "com\\.example\\..*",
                List.of(ARTIFACT_KEY_ID), List.of(BUILDER_ID), true));
        long currentConfig = governance.current().version();
        assertTrue(currentConfig > v1Config);

        AdmissionRecord v2 = service.submit(request);
        logChain("policy-source-changed-recheck", v2);
        assertEquals(AdmissionStatus.ADMITTED, v2.status(), "outcome still admitted");
        assertEquals(2, v2.revision(), "changed decision basis must open a new revision");
        assertEquals(v1.recordId(), v2.supersedesRecordId());
        assertEquals("newer-policy", v2.decision().policyId(),
                "conclusion must name the currently effective policy, not the stale one");
        assertEquals(currentConfig, v2.decision().configVersion(),
                "conclusion must be bound to the latest config version");

        // 旧历史记录保留、可查、不被改写
        AdmissionRecord history = store.findById(v1.recordId()).orElseThrow();
        assertEquals(AdmissionStatus.ADMITTED, history.status());
        assertEquals("default-policy", history.decision().policyId());
        assertEquals(v1Config, history.decision().configVersion());

        // 同一配置下重复提交：幂等归并，不再产生新记录
        AdmissionRecord again = service.submit(request);
        logChain("same-config-resubmit", again);
        assertEquals(v2.recordId(), again.recordId());
        assertEquals(2, again.revision());
        assertEquals(currentConfig, again.decision().configVersion());
    }

    @Test
    void sameOutcomeUnderSamePolicyButRotatedSignerKeyYieldsNewRevision() {
        // 策略来源不变但签名密钥轮换：判定依据变化，同样要起新修订
        AdmissionRequest request = fixedRequest();
        AdmissionRecord v1 = service.submit(request);
        assertEquals(AdmissionStatus.ADMITTED, v1.status());

        // 换一把密钥签名同一制品，并更新策略白名单（同 ID 替换）
        KeyPair newArtifactKey = TestFixtures.generateKeyPair();
        governance.registerKey(TestFixtures.trustedKey("artifact-key-2", newArtifactKey));
        governance.publishPolicy(new TrustPolicy("default-policy", 10, "com\\.example\\..*",
                List.of("artifact-key-2"), List.of(BUILDER_ID), true));
        byte[] content = "fixed-artifact-content".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String digest = com.github.highcumontoa.artifactadmissiongatejava.trust.CryptoSupport
                .sha256Hex(content);
        var provenance = TestFixtures.provenance("com.example.app", digest, BUILDER_ID,
                provenanceKey, PROVENANCE_KEY_ID);
        AdmissionRequest rekeyed = new AdmissionRequest("com.example.app", digest,
                java.util.Base64.getEncoder().encodeToString(content),
                TestFixtures.sign(newArtifactKey.getPrivate(), digest), "artifact-key-2", provenance);

        AdmissionRecord v2 = service.submit(rekeyed);
        logChain("signer-key-changed-recheck", v2);
        assertEquals(AdmissionStatus.ADMITTED, v2.status());
        assertEquals("artifact-key-2", v2.decision().signerKeyId());
        assertTrue(v2.decision().configVersion() > v1.decision().configVersion());
    }
}
