package com.github.highcumontoa.artifactadmissiongatejava.support;

import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.model.ProvenanceStatement;
import com.github.highcumontoa.artifactadmissiongatejava.trust.CryptoSupport;
import com.github.highcumontoa.artifactadmissiongatejava.trust.KeyState;
import com.github.highcumontoa.artifactadmissiongatejava.trust.TrustedKey;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/** 测试支撑：本地生成 Ed25519 密钥与签名，不依赖任何外部服务或真实凭据。 */
public final class TestFixtures {

    private TestFixtures() {
    }

    public static KeyPair generateKeyPair() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String sign(PrivateKey privateKey, String payload) {
        try {
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(privateKey);
            signer.update(payload.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signer.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static TrustedKey trustedKey(String keyId, KeyPair keyPair) {
        return new TrustedKey(keyId, keyPair.getPublic(), KeyState.ACTIVE,
                Instant.now().minusSeconds(60), null, null);
    }

    /** 构造一份完全合法的准入请求（可再按需篡改）。 */
    public static AdmissionRequest validRequest(String artifactId, KeyPair artifactKey, String artifactKeyId,
                                                KeyPair provenanceKey, String provenanceKeyId, String builderId) {
        byte[] content = ("payload-of-" + artifactId + "-" + UUID.randomUUID()).getBytes(StandardCharsets.UTF_8);
        String digest = CryptoSupport.sha256Hex(content);
        String signature = sign(artifactKey.getPrivate(), digest);
        ProvenanceStatement provenance = provenance(artifactId, digest, builderId, provenanceKey, provenanceKeyId);
        return new AdmissionRequest(artifactId, digest,
                Base64.getEncoder().encodeToString(content), signature, artifactKeyId, provenance);
    }

    public static ProvenanceStatement provenance(String artifactId, String digest, String builderId,
                                                 KeyPair provenanceKey, String provenanceKeyId) {
        long issuedAt = Instant.now().getEpochSecond();
        String statementId = "stmt-" + UUID.randomUUID();
        ProvenanceStatement unsigned = new ProvenanceStatement(
                statementId, artifactId, digest, builderId, issuedAt, provenanceKeyId, null);
        String signature = sign(provenanceKey.getPrivate(), unsigned.canonicalPayload());
        return new ProvenanceStatement(statementId, artifactId, digest, builderId,
                issuedAt, provenanceKeyId, signature);
    }
}
