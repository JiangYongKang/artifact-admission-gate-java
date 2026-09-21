package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.github.highcumontoa.artifactadmissiongatejava.config.GateProperties;
import com.github.highcumontoa.artifactadmissiongatejava.config.TrustBootstrap;
import com.github.highcumontoa.artifactadmissiongatejava.core.admission.AdmissionException;
import com.github.highcumontoa.artifactadmissiongatejava.core.crypto.JacksonSupport;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.Effect;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyRule;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.TrustPolicy;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.ConstraintType;
import com.github.highcumontoa.artifactadmissiongatejava.domain.RejectReason;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** 启动引导：从本地目录装载信任根与策略；目录缺失时空信任启动（失败关闭），策略冲突拒绝引导。 */
class TrustBootstrapTest {

    @TempDir
    Path dir;

    private final com.github.highcumontoa.artifactadmissiongatejava.core.crypto.CryptoService crypto =
            new com.github.highcumontoa.artifactadmissiongatejava.core.crypto.JdkCryptoService();

    @Test
    void loadsKeysAndPoliciesFromDirectories() throws Exception {
        Path trustDir = dir.resolve("trust");
        Path keyDir = trustDir.resolve("root-a");
        Files.createDirectories(keyDir);
        var pair = TestFixtures.generateRsaKey();
        Files.writeString(keyDir.resolve("public.pem"), crypto.toPem(pair.getPublic()));
        Files.writeString(keyDir.resolve("meta.json"),
                "{\"state\":\"ACTIVE\"}");

        Path polDir = dir.resolve("policies");
        Files.createDirectories(polDir);
        TrustPolicy policy = new TrustPolicy("boot-policy", List.of(
                new PolicyRule("s", ConstraintType.SIGNER, "root-a", Effect.ALLOW, 1),
                new PolicyRule("b", ConstraintType.BUILD_SOURCE, "ci", Effect.ALLOW, 1),
                new PolicyRule("a", ConstraintType.ARTIFACT_ID, "art", Effect.ALLOW, 1)));
        JacksonSupport.mapper().writerWithDefaultPrettyPrinter()
                .writeValue(polDir.resolve("p.json").toFile(), policy);

        GateProperties props = new GateProperties();
        props.setTrustDir(trustDir.toString());
        props.setPoliciesDir(polDir.toString());
        var trustStore = new com.github.highcumontoa.artifactadmissiongatejava.core.trust.InMemoryTrustStore();
        var policyRepo = new com.github.highcumontoa.artifactadmissiongatejava.core.policy.InMemoryPolicyRepository();
        TrustBootstrap bootstrap = new TrustBootstrap(props, trustStore, policyRepo, crypto);
        bootstrap.run(new org.springframework.boot.DefaultApplicationArguments());

        assertTrue(trustStore.keyIds().contains("root-a"));
        assertNotNull(policyRepo.get("boot-policy"));
        assertNotNull(trustStore.get("root-a").getPublicKey());
    }

    @Test
    void missingDirsBootstrapEmptyFailClosed() {
        GateProperties props = new GateProperties();
        var trustStore = new com.github.highcumontoa.artifactadmissiongatejava.core.trust.InMemoryTrustStore();
        var policyRepo = new com.github.highcumontoa.artifactadmissiongatejava.core.policy.InMemoryPolicyRepository();
        TrustBootstrap bootstrap = new TrustBootstrap(props, trustStore, policyRepo, crypto);
        assertDoesNotThrow(() -> bootstrap.run(new org.springframework.boot.DefaultApplicationArguments()));
        assertTrue(trustStore.keyIds().isEmpty());
        // 空信任库：任何密钥评估都不可信
        var verdict = trustStore.assess("anything", java.time.Instant.now(), java.time.Instant.now());
        assertFalse(verdict.trusted());
        assertEquals(RejectReason.KEY_UNTRUSTED, verdict.reason());
    }

    @Test
    void conflictingPolicyFileAbortsBootstrap() throws Exception {
        Path polDir = dir.resolve("policies-bad");
        Files.createDirectories(polDir);
        TrustPolicy bad = new TrustPolicy("bad", List.of(
                new PolicyRule("s1", ConstraintType.SIGNER, "k", Effect.ALLOW, 1),
                new PolicyRule("s2", ConstraintType.SIGNER, "k", Effect.DENY, 1),
                new PolicyRule("b", ConstraintType.BUILD_SOURCE, "ci", Effect.ALLOW, 1),
                new PolicyRule("a", ConstraintType.ARTIFACT_ID, "art", Effect.ALLOW, 1)));
        JacksonSupport.mapper().writeValue(polDir.resolve("bad.json").toFile(), bad);

        GateProperties props = new GateProperties();
        props.setPoliciesDir(polDir.toString());
        var trustStore = new com.github.highcumontoa.artifactadmissiongatejava.core.trust.InMemoryTrustStore();
        var policyRepo = new com.github.highcumontoa.artifactadmissiongatejava.core.policy.InMemoryPolicyRepository();
        TrustBootstrap bootstrap = new TrustBootstrap(props, trustStore, policyRepo, crypto);
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> bootstrap.run(new org.springframework.boot.DefaultApplicationArguments()));
        assertEquals(RejectReason.POLICY_CONFLICT, ex.getReason());
        assertNull(policyRepo.get("bad"));
    }
}
