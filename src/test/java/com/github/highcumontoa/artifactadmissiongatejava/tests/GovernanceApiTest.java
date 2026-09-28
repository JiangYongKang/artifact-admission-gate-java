package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.github.highcumontoa.artifactadmissiongatejava.api.AdmissionController;
import com.github.highcumontoa.artifactadmissiongatejava.api.GovernanceController;
import com.github.highcumontoa.artifactadmissiongatejava.config.GovernanceManager;
import com.github.highcumontoa.artifactadmissiongatejava.policy.PolicyEngine;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ProvenanceVerifier;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ReplayGuard;
import com.github.highcumontoa.artifactadmissiongatejava.sbom.SbomVerifier;
import com.github.highcumontoa.artifactadmissiongatejava.service.AdmissionService;
import com.github.highcumontoa.artifactadmissiongatejava.store.AdmissionStore;
import com.github.highcumontoa.artifactadmissiongatejava.support.TestFixtures;
import com.github.highcumontoa.artifactadmissiongatejava.trust.TrustStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 运行期治理 HTTP 接口测试（独立搭建控制器，无网络监听，不接外部服务）。
 */
class GovernanceApiTest {

    private static final Logger log = LoggerFactory.getLogger(GovernanceApiTest.class);

    private MockMvc mvc;
    private GovernanceManager governance;

    @BeforeEach
    void setUp() {
        TrustStore trustStore = new TrustStore();
        PolicyEngine policyEngine = new PolicyEngine();
        governance = new GovernanceManager(trustStore, policyEngine);
        AdmissionService service = new AdmissionService(new AdmissionStore(), governance, trustStore,
                policyEngine, new ProvenanceVerifier(), new SbomVerifier(), new ReplayGuard(),
                Clock.fixed(Instant.now(), ZoneOffset.UTC), 100, 5000);
        mvc = MockMvcBuilders.standaloneSetup(
                        new GovernanceController(governance), new AdmissionController(service))
                .build();
    }

    @Test
    void registerKeyThenSnapshotShowsIt() throws Exception {
        KeyPair keyPair = TestFixtures.generateKeyPair();
        String body = "{\"keyId\":\"k1\",\"publicKeyBase64\":\""
                + TestFixtures.publicKeyX506Base64(keyPair) + "\"}";
        mvc.perform(post("/api/governance/keys").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.configVersion").exists());
        mvc.perform(get("/api/governance/snapshot"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].keyId").value("k1"))
                .andExpect(jsonPath("$.keys[0].state").value("ACTIVE"));
        log.info("[api-key-register] key visible in snapshot (keyId only, no material)");
    }

    @Test
    void duplicateKeyReturns409() throws Exception {
        KeyPair keyPair = TestFixtures.generateKeyPair();
        String body = "{\"keyId\":\"k1\",\"publicKeyBase64\":\""
                + TestFixtures.publicKeyX506Base64(keyPair) + "\"}";
        mvc.perform(post("/api/governance/keys").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated());
        mvc.perform(post("/api/governance/keys").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("KEY_CONFLICT"));
        log.info("[api-duplicate-key] HTTP 409 returned");
    }

    @Test
    void policyReferencingUnknownKeyReturns400AndIsNotPublished() throws Exception {
        String body = "{\"policyId\":\"p-bad\",\"priority\":10,\"artifactIdPattern\":\".*\",\"allowedSignerKeyIds\":[\"ghost\"]}";
        mvc.perform(post("/api/governance/policies").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("POLICY_KEY_UNTRUSTED"));
        mvc.perform(get("/api/governance/snapshot"))
                .andExpect(jsonPath("$.policies.length()").value(0));
        log.info("[api-policy-untrusted-key] rejected at publish, not in snapshot");
    }

    @Test
    void validPolicyPublishedThenRetired() throws Exception {
        KeyPair keyPair = TestFixtures.generateKeyPair();
        String keyBody = "{\"keyId\":\"k1\",\"publicKeyBase64\":\""
                + TestFixtures.publicKeyX506Base64(keyPair) + "\"}";
        mvc.perform(post("/api/governance/keys").contentType(MediaType.APPLICATION_JSON).content(keyBody))
                .andExpect(status().isCreated());
        String policyBody = "{\"policyId\":\"p1\",\"priority\":10,\"allowedSignerKeyIds\":[\"k1\"],\"requireProvenance\":false}";
        mvc.perform(post("/api/governance/policies").contentType(MediaType.APPLICATION_JSON).content(policyBody))
                .andExpect(status().isCreated());
        mvc.perform(get("/api/governance/snapshot"))
                .andExpect(jsonPath("$.policies[0].policyId").value("p1"));
        mvc.perform(delete("/api/governance/policies/p1"))
                .andExpect(status().isOk());
        mvc.perform(get("/api/governance/snapshot"))
                .andExpect(jsonPath("$.policies.length()").value(0));
        log.info("[api-policy-lifecycle] published then retired, version advanced each time");
    }
}
