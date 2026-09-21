package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.github.highcumontoa.artifactadmissiongatejava.api.AdmissionResponse;
import com.github.highcumontoa.artifactadmissiongatejava.core.TimeSource;
import com.github.highcumontoa.artifactadmissiongatejava.core.admission.AdmissionService;
import com.github.highcumontoa.artifactadmissiongatejava.core.audit.AuditLog;
import com.github.highcumontoa.artifactadmissiongatejava.domain.AuditEvent;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 安全：公钥/私钥材料与签名原文不得出现在对外响应或审计日志中。
 * 通过检查响应/审计序列化文本中是否包含密钥 DER 的 Base64 片段来验证。
 */
class SecretMaterialLeakTest extends BaseAdmissionTest {

    @Autowired
    private AdmissionService admissionService;
    @Autowired
    private AuditLog auditLog;
    @Autowired
    private TimeSource timeSource;

    @Test
    void responseAndAuditNeverContainKeyMaterial() {
        TestFixtures.KeyMaterial key = registerDefaultKey(TestFixtures.generateRsaKey());
        configureAllowAllPolicy();
        TestFixtures.Bundle bundle = TestFixtures.writeSignedBundle(
                tempDir, key, "leak-check", BUILD_SOURCE, ARTIFACT_ID,
                timeSource.now().minusSeconds(10), null, "stmt-leak",
                crypto, envelopes, attestations);

        AdmissionResponse response = admissionService.submit(bundle.requestNoSbom(POLICY));

        // 从 PEM 提取公钥 DER 的 base64，取其中较长且稳定的片段作为“材料指纹”
        String pem;
        try {
            pem = java.nio.file.Files.readString(key.pem());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        String derB64 = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        String fragment = derB64.substring(40, 120);

        String responseText = response.toString();
        assertFalse(responseText.contains(fragment), "响应中不得出现公钥材料");
        for (AuditEvent event : auditLog.events()) {
            String text = event.toString();
            assertFalse(text.contains(fragment), "审计日志中不得出现公钥材料");
        }

        // 签名原文（base64）也不应出现在审计 detail 中
        com.github.highcumontoa.artifactadmissiongatejava.core.crypto.SignatureEnvelope sig = envelopes.read(bundle.signature());
        String sigFragment = sig.signatureBase64().substring(8, 60);
        for (AuditEvent event : auditLog.events()) {
            assertFalse(event.toString().contains(sigFragment), "审计中不得出现签名原文");
        }
        // 摘要与声明 id 必须可追溯（应出现）
        assertTrue(auditLog.events().stream().anyMatch(e -> bundle.digest().equals(e.artifactDigest())));
        assertTrue(auditLog.events().stream().anyMatch(e -> "stmt-leak".equals(e.statementId())));
        // keyId 是标识符不是密钥材料，可以出现
        assertEquals(DEFAULT_KEY, response.signerKeyId());
    }
}
