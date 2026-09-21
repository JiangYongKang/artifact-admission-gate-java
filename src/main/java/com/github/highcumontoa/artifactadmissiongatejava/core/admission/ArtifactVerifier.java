package com.github.highcumontoa.artifactadmissiongatejava.core.admission;

import com.github.highcumontoa.artifactadmissiongatejava.core.crypto.CryptoService;
import com.github.highcumontoa.artifactadmissiongatejava.core.crypto.EnvelopeCodec;
import com.github.highcumontoa.artifactadmissiongatejava.core.crypto.SignatureEnvelope;
import com.github.highcumontoa.artifactadmissiongatejava.core.trust.TrustedKey;
import com.github.highcumontoa.artifactadmissiongatejava.core.trust.TrustStore;
import com.github.highcumontoa.artifactadmissiongatejava.core.trust.TrustVerdict;
import com.github.highcumontoa.artifactadmissiongatejava.domain.RejectReason;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 制品侧联合校验的前半段：
 * - 读取制品并计算 SHA-256，与请求中声称的摘要比对（DIGEST_MISMATCH）；
 * - 读取签名信封；信封缺失/损坏按 SIGNATURE_INVALID 失败关闭；
 * - 密钥信任状态判定（KEY_*，原因可区分）；
 * - 信封声明的 signedDigest 必须等于实际摘要，且密码学验签必须通过（SIGNATURE_INVALID）。
 */
@Component
public class ArtifactVerifier {

    private final CryptoService cryptoService;
    private final EnvelopeCodec envelopeCodec;
    private final TrustStore trustStore;

    public ArtifactVerifier(CryptoService cryptoService, EnvelopeCodec envelopeCodec, TrustStore trustStore) {
        this.cryptoService = cryptoService;
        this.envelopeCodec = envelopeCodec;
        this.trustStore = trustStore;
    }

    public record Result(boolean ok, RejectReason reason, String actualDigest,
                         SignatureEnvelope envelope, List<String> basis) {
    }

    public Result verify(Path artifactFile, String claimedDigest, Path signatureFile, Instant now) {
        List<String> basis = new ArrayList<>();
        if (artifactFile == null || !Files.isReadable(artifactFile)) {
            return new Result(false, RejectReason.BAD_REQUEST, null, null, List.of("artifact-unreadable"));
        }
        String actual = cryptoService.sha256Hex(artifactFile);
        basis.add("artifactDigest=" + actual);

        if (claimedDigest != null && !claimedDigest.isBlank() && !claimedDigest.equals(actual)) {
            basis.add("claimedDigest=" + claimedDigest + " != actualDigest=" + actual);
            return new Result(false, RejectReason.DIGEST_MISMATCH, actual, null, basis);
        }

        if (signatureFile == null || !Files.isReadable(signatureFile)) {
            return new Result(false, RejectReason.SIGNATURE_INVALID, actual, null,
                    List.of("signature-file-missing"));
        }
        SignatureEnvelope envelope;
        try {
            envelope = envelopeCodec.read(signatureFile);
        } catch (RuntimeException e) {
            return new Result(false, RejectReason.SIGNATURE_INVALID, actual, null,
                    List.of("signature-envelope-unreadable"));
        }
        if (envelope == null || envelope.keyId() == null || envelope.signatureBase64() == null
                || envelope.signedDigest() == null) {
            return new Result(false, RejectReason.SIGNATURE_INVALID, actual, envelope,
                    List.of("signature-envelope-incomplete"));
        }

        TrustVerdict verdict = trustStore.assess(envelope.keyId(), envelope.signedAt(), now);
        if (!verdict.trusted()) {
            basis.add("artifact-key " + envelope.keyId() + " -> " + verdict.reason());
            return new Result(false, verdict.reason(), actual, envelope, basis);
        }

        if (!actual.equals(envelope.signedDigest())) {
            basis.add("envelope-digest=" + envelope.signedDigest() + " != actual=" + actual);
            return new Result(false, RejectReason.SIGNATURE_INVALID, actual, envelope, basis);
        }

        TrustedKey key = trustStore.get(envelope.keyId());
        if (!cryptoService.verifyDigestSignature(key.getPublicKey(), actual, envelope.signatureBase64())) {
            return new Result(false, RejectReason.SIGNATURE_INVALID, actual, envelope,
                    List.of("rsa-verify-failed keyId=" + envelope.keyId()));
        }
        basis.add("artifact-signature=valid keyId=" + envelope.keyId());
        return new Result(true, null, actual, envelope, basis);
    }
}
