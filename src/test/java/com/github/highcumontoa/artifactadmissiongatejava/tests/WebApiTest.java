package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.highcumontoa.artifactadmissiongatejava.api.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.core.crypto.JacksonSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.file.Path;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** 对外 HTTP 契约：状态明确、错误可解释、不泄漏密钥材料。 */
@SpringBootTest(properties = {
        "admission.gate.trust-dir=",
        "admission.gate.policies-dir="
})
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class WebApiTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private com.github.highcumontoa.artifactadmissiongatejava.core.crypto.CryptoService crypto;
    @Autowired
    private com.github.highcumontoa.artifactadmissiongatejava.core.crypto.EnvelopeCodec envelopes;
    @Autowired
    private com.github.highcumontoa.artifactadmissiongatejava.core.attestation.AttestationCodec attestations;
    @Autowired
    private com.github.highcumontoa.artifactadmissiongatejava.core.trust.TrustStore trustStore;
    @Autowired
    private com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyRepository policyRepository;
    @Autowired
    private com.github.highcumontoa.artifactadmissiongatejava.core.TimeSource timeSource;

    @org.junit.jupiter.api.io.TempDir
    static Path tempDir;

    private final ObjectMapper mapper = JacksonSupport.mapper();
    private TestFixtures.KeyMaterial key;

    @BeforeEach
    void setup() {
        if (key == null) {
            key = TestFixtures.writeKey(tempDir, "web-key", TestFixtures.generateRsaKey(), crypto);
            trustStore.register(new com.github.highcumontoa.artifactadmissiongatejava.core.trust.TrustedKey(
                    "web-key", key.keyPair().getPublic(),
                    com.github.highcumontoa.artifactadmissiongatejava.domain.KeyState.ACTIVE,
                    null, null, null));
            policyRepository.put(new com.github.highcumontoa.artifactadmissiongatejava.core.policy.TrustPolicy(
                    "web-policy", java.util.List.of(
                    new com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyRule(
                            "s", com.github.highcumontoa.artifactadmissiongatejava.core.policy.ConstraintType.SIGNER,
                            "web-key", com.github.highcumontoa.artifactadmissiongatejava.core.policy.Effect.ALLOW, 100),
                    new com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyRule(
                            "b", com.github.highcumontoa.artifactadmissiongatejava.core.policy.ConstraintType.BUILD_SOURCE,
                            "ci://web", com.github.highcumontoa.artifactadmissiongatejava.core.policy.Effect.ALLOW, 100),
                    new com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyRule(
                            "a", com.github.highcumontoa.artifactadmissiongatejava.core.policy.ConstraintType.ARTIFACT_ID,
                            "web:1", com.github.highcumontoa.artifactadmissiongatejava.core.policy.Effect.ALLOW, 100))));
        }
    }

    @Test
    void submitAndQueryReturnExplicitTerminalStatus() throws Exception {
        TestFixtures.Bundle bundle = TestFixtures.writeSignedBundle(
                tempDir, key, "web-content", "ci://web", "web:1",
                Instant.now().minusSeconds(10), null, "stmt-web-" + System.nanoTime(),
                crypto, envelopes, attestations);
        AdmissionRequest req = bundle.requestNoSbom("web-policy");

        MvcResult result = mockMvc.perform(post("/api/admissions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ADMITTED"))
                .andExpect(jsonPath("$.rejectReason").doesNotExist())
                .andReturn();
        JsonNode node = mapper.readTree(result.getResponse().getContentAsString());
        String id = node.get("admissionId").asText();
        assertFalse(node.has("publicKey"), "响应不得包含任何密钥材料字段");

        mockMvc.perform(get("/api/admissions/" + id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ADMITTED"))
                .andExpect(jsonPath("$.artifactDigest").value(bundle.digest()));
    }

    @Test
    void rejectedSubmissionReturnsDistinguishableReason() throws Exception {
        TestFixtures.Bundle bundle = TestFixtures.writeSignedBundle(
                tempDir, key, "web-reject", "ci://web", "web:1",
                Instant.now().minusSeconds(10), null, "stmt-web-rej-" + System.nanoTime(),
                crypto, envelopes, attestations);
        AdmissionRequest req = bundle.requestNoSbom("missing-policy");

        // 拒绝是明确的业务终态：HTTP 200，正文用 REJECTED + 可区分原因码表达，而非不可解释错误
        mockMvc.perform(post("/api/admissions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("REJECTED"))
                .andExpect(jsonPath("$.rejectReason").value("POLICY_MISSING"))
                .andExpect(jsonPath("$.admissionId").exists());
    }

    @Test
    void unknownAdmissionIsExplainable404() throws Exception {
        mockMvc.perform(get("/api/admissions/no-such-id"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errorCode").value("NOT_FOUND"));
    }

    @Test
    void malformedJsonIsBadRequest() throws Exception {
        mockMvc.perform(post("/api/admissions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ not-json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("BAD_REQUEST"));
    }
}
