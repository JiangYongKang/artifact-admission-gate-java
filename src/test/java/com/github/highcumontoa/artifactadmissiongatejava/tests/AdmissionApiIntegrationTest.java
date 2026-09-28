package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.model.ComponentManifest;
import com.github.highcumontoa.artifactadmissiongatejava.model.ProvenanceStatement;
import com.github.highcumontoa.artifactadmissiongatejava.support.TestFixtures;
import com.github.highcumontoa.artifactadmissiongatejava.trust.CryptoSupport;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 端到端接口测试：运行期治理 → 准入 → 成分清单 → 撤销后复核，全程走 HTTP，仅本地、无真实凭据。
 */
@SpringBootTest
@AutoConfigureMockMvc
class AdmissionApiIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(AdmissionApiIntegrationTest.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private MockMvc mvc;

    private String x509PublicBase64(KeyPair kp) {
        return Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
    }

    private JsonNode postJson(String url, Object body, int expectedStatus) throws Exception {
        String resp = mvc.perform(post(url).contentType(MediaType.APPLICATION_JSON)
                        .content(MAPPER.writeValueAsString(body)))
                .andExpect(status().is(expectedStatus))
                .andReturn().getResponse().getContentAsString();
        log.info("POST {} -> {} body={}", url, expectedStatus, resp);
        return MAPPER.readTree(resp);
    }

    @Test
    void governThenAdmitThenRevokeThenRecheckOverHttp() throws Exception {
        KeyPair artifactKey = TestFixtures.generateKeyPair();
        KeyPair provenanceKey = TestFixtures.generateKeyPair();
        String aKeyId = "http-artifact-key-" + UUID.randomUUID();
        String pKeyId = "http-prov-key-" + UUID.randomUUID();

        // 1. 运行期注册两把密钥
        postJson("/api/governance/keys", Map.of(
                "keyId", aKeyId, "publicKeyBase64", x509PublicBase64(artifactKey)), 200);
        postJson("/api/governance/keys", Map.of(
                "keyId", pKeyId, "publicKeyBase64", x509PublicBase64(provenanceKey)), 200);

        // 2. 发布引用未知密钥的策略 → 422，且不生效
        JsonNode rejected = postJson("/api/governance/policies", Map.of(
                "policyId", "bad", "priority", 10, "artifactIdPattern", ".*",
                "allowedSignerKeyIds", List.of("ghost-key"),
                "requireProvenance", true), 422);
        org.junit.jupiter.api.Assertions.assertEquals("POLICY_KEY_NOT_TRUSTED", rejected.get("code").asText());

        // 3. 发布合法策略：要求来源证明与成分清单，组件限定 com.acme.*
        postJson("/api/governance/policies", Map.of(
                "policyId", "http-policy", "priority", 10, "artifactIdPattern", ".*",
                "allowedSignerKeyIds", List.of(aKeyId),
                "allowedBuilderIds", List.of("http-builder"),
                "requireProvenance", true,
                "requireManifest", true,
                "allowedComponentPatterns", List.of("com\\.acme\\..*")), 200);

        // 4. 构造合法请求（含绑定正确、组件合规的清单）
        byte[] content = ("http-artifact-" + UUID.randomUUID()).getBytes(StandardCharsets.UTF_8);
        String digest = CryptoSupport.sha256Hex(content);
        String artifactSig = TestFixtures.sign(artifactKey.getPrivate(), digest);
        long issuedAt = Instant.now().getEpochSecond();
        String statementId = "http-stmt-" + UUID.randomUUID();
        String provPayload = String.join("|", statementId, "http-app", digest, "http-builder",
                String.valueOf(issuedAt));
        String provSig = TestFixtures.sign(provenanceKey.getPrivate(), provPayload);
        ProvenanceStatement provenance = new ProvenanceStatement(statementId, "http-app", digest,
                "http-builder", issuedAt, pKeyId, provSig);
        ComponentManifest manifest = new ComponentManifest("http-sbom-" + UUID.randomUUID(),
                "http-app", digest, List.of(TestFixtures.component("com.acme.core", "1.0")));
        AdmissionRequest request = new AdmissionRequest("http-app", digest,
                Base64.getEncoder().encodeToString(content), artifactSig, aKeyId, provenance, manifest);

        JsonNode admitted = postJson("/api/admissions", request, 200);
        org.junit.jupiter.api.Assertions.assertEquals("ADMITTED", admitted.get("status").asText());
        org.junit.jupiter.api.Assertions.assertEquals(1, admitted.get("revision").asInt());

        // 5. 运行期撤销制品签名密钥后再次提交同一请求 → 按最新状态拒绝，并产生修订版
        mvc.perform(post("/api/governance/keys/" + aKeyId + "/revoke"))
                .andExpect(status().isOk());
        JsonNode rechecked = postJson("/api/admissions", request, 200);
        org.junit.jupiter.api.Assertions.assertEquals("REJECTED", rechecked.get("status").asText());
        org.junit.jupiter.api.Assertions.assertEquals("KEY_REVOKED",
                rechecked.get("decision").get("reason").asText());
        org.junit.jupiter.api.Assertions.assertEquals(2, rechecked.get("revision").asInt());

        // 6. 快照查询可见密钥已撤销
        mvc.perform(get("/api/governance/snapshot"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[?(@.keyId=='" + aKeyId + "')].state").value(
                        org.hamcrest.Matchers.hasItem("REVOKED")));
    }

    @Test
    void manifestWithDisallowedComponentIsRejectedOverHttp() throws Exception {
        KeyPair artifactKey = TestFixtures.generateKeyPair();
        KeyPair provenanceKey = TestFixtures.generateKeyPair();
        String aKeyId = "http-artifact-key2-" + UUID.randomUUID();
        String pKeyId = "http-prov-key2-" + UUID.randomUUID();
        postJson("/api/governance/keys", Map.of(
                "keyId", aKeyId, "publicKeyBase64", x509PublicBase64(artifactKey)), 200);
        postJson("/api/governance/keys", Map.of(
                "keyId", pKeyId, "publicKeyBase64", x509PublicBase64(provenanceKey)), 200);
        postJson("/api/governance/policies", Map.of(
                "policyId", "http-policy2-" + UUID.randomUUID(), "priority", 5,
                "artifactIdPattern", ".*", "allowedSignerKeyIds", List.of(aKeyId),
                "allowedBuilderIds", List.of("b2"), "requireProvenance", true,
                "requireManifest", true,
                "allowedComponentPatterns", List.of("com\\.acme\\..*")), 200);

        byte[] content = "x".getBytes(StandardCharsets.UTF_8);
        String digest = CryptoSupport.sha256Hex(content);
        String sig = TestFixtures.sign(artifactKey.getPrivate(), digest);
        ProvenanceStatement prov = TestFixtures.provenance("a2", digest, "b2", provenanceKey, pKeyId);
        ComponentManifest manifest = TestFixtures.manifest("a2", digest,
                List.of(TestFixtures.component("com.virus.x", "1.0")));
        AdmissionRequest req = new AdmissionRequest("a2", digest,
                Base64.getEncoder().encodeToString(content), sig, aKeyId, prov, manifest);
        JsonNode resp = postJson("/api/admissions", req, 200);
        org.junit.jupiter.api.Assertions.assertEquals("SBOM_COMPONENT_VIOLATION",
                resp.get("decision").get("reason").asText());
    }
}
