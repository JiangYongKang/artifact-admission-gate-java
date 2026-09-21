package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.github.highcumontoa.artifactadmissiongatejava.core.attestation.AttestationCodec;
import com.github.highcumontoa.artifactadmissiongatejava.core.crypto.CryptoService;
import com.github.highcumontoa.artifactadmissiongatejava.core.crypto.EnvelopeCodec;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.Effect;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyRule;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.TrustPolicy;
import com.github.highcumontoa.artifactadmissiongatejava.core.admission.AdmissionRepository;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyRepository;
import com.github.highcumontoa.artifactadmissiongatejava.core.trust.TrustStore;
import com.github.highcumontoa.artifactadmissiongatejava.domain.KeyState;
import com.github.highcumontoa.artifactadmissiongatejava.core.trust.TrustedKey;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;

/**
 * 测试基类：默认装载一个 ACTIVE 信任根与一条全 ALLOW 策略，
 * 每个测试方法独立的内存组件（@SpringBootTest 默认上下文内组件为单例，
 * 因此用例之间使用不同 keyId/statementId，并在需要时显式重置）。
 */
@SpringBootTest(properties = {
        "admission.gate.trust-dir=",
        "admission.gate.policies-dir="
})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public abstract class BaseAdmissionTest {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    @TempDir
    protected Path tempDir;

    @Autowired
    protected CryptoService crypto;
    @Autowired
    protected EnvelopeCodec envelopes;
    @Autowired
    protected AttestationCodec attestations;
    @Autowired
    protected TrustStore trustStore;
    @Autowired
    protected PolicyRepository policyRepository;
    @Autowired
    protected AdmissionRepository admissionRepository;

    @org.junit.jupiter.api.BeforeEach
    void resetAdmissionState() {
        // 每个用例从空的准入记录/重放索引开始，避免类内方法间相互累积
        admissionRepository.clear();
    }

    protected static final String DEFAULT_KEY = "test-key-1";
    protected static final String POLICY = "strict-policy";
    protected static final String BUILD_SOURCE = "ci://build-farm/job-42";
    protected static final String ARTIFACT_ID = "app/core:1.0.0";

    protected TestFixtures.KeyMaterial registerDefaultKey(KeyPair pair) {
        TestFixtures.KeyMaterial material = TestFixtures.writeKey(tempDir, DEFAULT_KEY, pair, crypto);
        trustStore.register(new TrustedKey(DEFAULT_KEY, pair.getPublic(),
                KeyState.ACTIVE, null, null, null));
        return material;
    }

    protected void configureAllowAllPolicy() {
        policyRepository.put(new TrustPolicy(POLICY, List.of(
                new PolicyRule("allow-signer",
                        com.github.highcumontoa.artifactadmissiongatejava.core.policy.ConstraintType.SIGNER,
                        DEFAULT_KEY, Effect.ALLOW, 100),
                new PolicyRule("allow-source",
                        com.github.highcumontoa.artifactadmissiongatejava.core.policy.ConstraintType.BUILD_SOURCE,
                        BUILD_SOURCE, Effect.ALLOW, 100),
                new PolicyRule("allow-artifact",
                        com.github.highcumontoa.artifactadmissiongatejava.core.policy.ConstraintType.ARTIFACT_ID,
                        ARTIFACT_ID, Effect.ALLOW, 100)
        )));
    }
}
