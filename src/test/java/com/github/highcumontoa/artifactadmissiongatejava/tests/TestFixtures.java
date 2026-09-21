package com.github.highcumontoa.artifactadmissiongatejava.tests;

import com.github.highcumontoa.artifactadmissiongatejava.api.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.core.attestation.Attestation;
import com.github.highcumontoa.artifactadmissiongatejava.core.attestation.AttestationCodec;
import com.github.highcumontoa.artifactadmissiongatejava.core.attestation.ProvenanceClaims;
import com.github.highcumontoa.artifactadmissiongatejava.core.crypto.CryptoService;
import com.github.highcumontoa.artifactadmissiongatejava.core.crypto.EnvelopeCodec;
import com.github.highcumontoa.artifactadmissiongatejava.core.crypto.SignatureEnvelope;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.UUID;

/**
 * 测试夹具：在临时目录中生成密钥、制品、签名信封、来源证明与 SBOM。
 * 全部本地生成、确定性可控，不依赖任何真实凭据或外部资源。
 */
public final class TestFixtures {

    public record KeyMaterial(String keyId, KeyPair keyPair, Path pem) {
    }

    public record Bundle(Path artifact, Path signature, Path attestation, Path sbom,
                         String digest, String statementId) {
        public AdmissionRequest request(String policyId) {
            return new AdmissionRequest(
                    artifact.toString(), digest, signature.toString(),
                    attestation.toString(), sbom == null ? null : sbom.toString(), policyId);
        }

        public AdmissionRequest requestNoSbom(String policyId) {
            return new AdmissionRequest(
                    artifact.toString(), digest, signature.toString(),
                    attestation.toString(), null, policyId);
        }
    }

    private TestFixtures() {
    }

    public static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static KeyMaterial writeKey(Path dir, String keyId, KeyPair pair, CryptoService crypto) {
        try {
            Path pem = dir.resolve(keyId + ".pem");
            Files.writeString(pem, crypto.toPem(pair.getPublic()));
            return new KeyMaterial(keyId, pair, pem);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static Bundle writeSignedBundle(Path dir, KeyMaterial key, String content,
                                           String buildSource, String artifactId,
                                           Instant signedAt, String sbomContent,
                                           CryptoService crypto, EnvelopeCodec envelopes,
                                           AttestationCodec attestations) {
        return writeSignedBundle(dir, key, content, buildSource, artifactId, signedAt,
                sbomContent, UUID.randomUUID().toString(), crypto, envelopes, attestations);
    }

    public static Bundle writeSignedBundle(Path dir, KeyMaterial key, String content,
                                           String buildSource, String artifactId,
                                           Instant signedAt, String sbomContent, String statementId,
                                           CryptoService crypto, EnvelopeCodec envelopes,
                                           AttestationCodec attestations) {
        try {
            Path artifact = dir.resolve("artifact-" + statementId + ".bin");
            Files.write(artifact, content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String digest = crypto.sha256Hex(artifact);

            SignatureEnvelope artifactSig = crypto.signDigest(
                    new CryptoService.PrivateKeyHolder(key.keyPair().getPrivate()),
                    key.keyId(), digest, signedAt);
            Path sigFile = dir.resolve("artifact-" + statementId + ".sig.json");
            envelopes.write(sigFile, artifactSig);

            String sbomDigest = null;
            Path sbomFile = null;
            if (sbomContent != null) {
                sbomFile = dir.resolve("sbom-" + statementId + ".json");
                Files.writeString(sbomFile, sbomContent);
                sbomDigest = crypto.sha256Hex(sbomFile);
            }

            Attestation attestation = new Attestation(
                    statementId, digest, sbomDigest,
                    new ProvenanceClaims(buildSource, artifactId),
                    signedAt, null);
            String payloadDigest = attestationPayloadDigest(attestation, crypto);
            SignatureEnvelope attSig = crypto.signDigest(
                    new CryptoService.PrivateKeyHolder(key.keyPair().getPrivate()),
                    key.keyId(), payloadDigest, signedAt);
            Attestation signed = new Attestation(statementId, digest, sbomDigest,
                    new ProvenanceClaims(buildSource, artifactId), signedAt, attSig);
            Path attFile = dir.resolve("attestation-" + statementId + ".json");
            attestations.write(attFile, signed);

            return new Bundle(artifact, sigFile, attFile, sbomFile, digest, statementId);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** 用另一把私钥对相同摘要重新签名，模拟伪造/冒用密钥的签名。 */
    public static Bundle resignArtifactWith(Bundle base, KeyMaterial attacker,
                                            Instant signedAt,
                                            CryptoService crypto, EnvelopeCodec envelopes) {
        try {
            SignatureEnvelope forged = crypto.signDigest(
                    new CryptoService.PrivateKeyHolder(attacker.keyPair().getPrivate()),
                    attacker.keyId(), base.digest(), signedAt);
            envelopes.write(base.signature(), forged);
            return base;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** 翻转制品一个字节但不改签名，模拟摘要被篡改。 */
    public static void tamperArtifact(Bundle base) {
        try {
            byte[] bytes = Files.readAllBytes(base.artifact());
            bytes[0] = (byte) (bytes[0] ^ 0x01);
            Files.write(base.artifact(), bytes);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** 用另一把私钥重签证明载荷，但保留原制品摘要之外的声明内容可选篡改。 */
    public static void reSignAttestationWithWrongKey(Bundle base, KeyMaterial attacker,
                                                     CryptoService crypto, AttestationCodec codec) {
        try {
            Attestation original = codec.read(base.attestation());
            String payload = attestationPayloadDigest(original, crypto);
            SignatureEnvelope forged = crypto.signDigest(
                    new CryptoService.PrivateKeyHolder(attacker.keyPair().getPrivate()),
                    attacker.keyId(), payload, original.issuedAt());
            codec.write(base.attestation(), new Attestation(original.statementId(),
                    original.artifactDigest(), original.sbomDigest(), original.claims(),
                    original.issuedAt(), forged));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** 修改证明绑定的制品摘要（签名仍对旧载荷有效），模拟证明与制品不绑定。 */
    public static void rebindAttestationDigest(Bundle base, String otherDigest, AttestationCodec codec) {
        try {
            Attestation original = codec.read(base.attestation());
            codec.write(base.attestation(), new Attestation(original.statementId(),
                    otherDigest, original.sbomDigest(), original.claims(),
                    original.issuedAt(), original.signature()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** 破坏签名信封 JSON，模拟不可解析的签名。 */
    public static void corruptSignatureFile(Bundle base) {
        try {
            Files.writeString(base.signature(), "{ this is not valid json ");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** 破坏证明 JSON。 */
    public static void corruptAttestationFile(Bundle base) {
        try {
            Files.writeString(base.attestation(), "{ broken-attestation ");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** 修改 SBOM 文件内容，模拟清单与证明声明不一致。 */
    public static void tamperSbom(Bundle base, String newContent) {
        try {
            Files.writeString(base.sbom(), newContent);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** 与 AttestationVerifier.payloadDigest 的规范保持一致。 */
    public static String attestationPayloadDigest(Attestation a, CryptoService crypto) {
        String canonical = a.statementId() + "|"
                + a.artifactDigest() + "|"
                + (a.sbomDigest() == null ? "" : a.sbomDigest()) + "|"
                + a.claims().buildSource() + "|"
                + a.claims().artifactId() + "|"
                + a.issuedAt();
        return crypto.sha256Hex(canonical.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
