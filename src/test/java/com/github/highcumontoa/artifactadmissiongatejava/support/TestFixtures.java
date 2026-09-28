package com.github.highcumontoa.artifactadmissiongatejava.support;

import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.model.ProvenanceStatement;
import com.github.highcumontoa.artifactadmissiongatejava.model.SbomComponent;
import com.github.highcumontoa.artifactadmissiongatejava.model.SoftwareBillOfMaterials;
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
import java.util.List;
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

    /** 导出 X.509 Base64 公钥，供治理接口注册密钥使用。 */
    public static String publicKeyX506Base64(KeyPair keyPair) {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
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

    /** 用给定密钥为指定制品构造一份已签名的 SBOM。 */
    public static SoftwareBillOfMaterials sbom(String artifactId, String digest,
                                               List<SbomComponent> components,
                                               KeyPair sbomKey, String sbomKeyId) {
        String billId = "bill-" + UUID.randomUUID();
        SoftwareBillOfMaterials unsigned = new SoftwareBillOfMaterials(
                billId, artifactId, digest, components, sbomKeyId, null);
        String signature = sign(sbomKey.getPrivate(), unsigned.canonicalPayload());
        return new SoftwareBillOfMaterials(billId, artifactId, digest, components, sbomKeyId, signature);
    }

    public static List<SbomComponent> components(String... nameAtVersion) {
        return java.util.Arrays.stream(nameAtVersion)
                .map(spec -> {
                    int at = spec.indexOf('@');
                    return at < 0 ? new SbomComponent(spec, null)
                            : new SbomComponent(spec.substring(0, at), spec.substring(at + 1));
                })
                .toList();
    }

    /** 在合法请求上附带 SBOM（7 参新构造）。 */
    public static AdmissionRequest withSbom(AdmissionRequest request, SoftwareBillOfMaterials sbom) {
        return new AdmissionRequest(request.artifactId(), request.declaredDigest(),
                request.contentBase64(), request.signatureBase64(), request.signerKeyId(),
                request.provenance(), sbom);
    }
}
