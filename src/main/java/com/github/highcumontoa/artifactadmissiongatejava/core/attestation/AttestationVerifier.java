package com.github.highcumontoa.artifactadmissiongatejava.core.attestation;

import com.github.highcumontoa.artifactadmissiongatejava.core.crypto.CryptoService;
import com.github.highcumontoa.artifactadmissiongatejava.core.trust.TrustedKey;
import com.github.highcumontoa.artifactadmissiongatejava.core.trust.TrustStore;
import com.github.highcumontoa.artifactadmissiongatejava.core.trust.TrustVerdict;
import com.github.highcumontoa.artifactadmissiongatejava.domain.RejectReason;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 来源证明校验：
 * - 证明结构完整（statementId / artifactDigest / 签名信封不得缺失），否则 ATTESTATION_MALFORMED；
 * - artifactDigest 必须与制品实际摘要一致，否则 ATTESTATION_NOT_BOUND；
 * - 签名密钥必须通过信任根状态判定（撤销/过期/轮换/不可信均可区分）；
 * - 签名必须在密码学意义上覆盖证明摘要，否则 SIGNATURE_INVALID。
 */
@Component
public class AttestationVerifier {

    private final CryptoService cryptoService;
    private final TrustStore trustStore;

    public AttestationVerifier(CryptoService cryptoService, TrustStore trustStore) {
        this.cryptoService = cryptoService;
        this.trustStore = trustStore;
    }

    /** 计算证明载荷（除签名字段外的稳定 JSON 字节）的摘要，作为被签名对象。 */
    public String payloadDigest(Attestation attestation) {
        String canonical = attestation.statementId() + "|"
                + attestation.artifactDigest() + "|"
                + (attestation.sbomDigest() == null ? "" : attestation.sbomDigest()) + "|"
                + attestation.claims().buildSource() + "|"
                + attestation.claims().artifactId() + "|"
                + attestation.issuedAt();
        return cryptoService.sha256Hex(canonical.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    public Result verify(Attestation attestation, String expectedArtifactDigest, Instant now) {
        List<String> basis = new ArrayList<>();
        if (attestation == null) {
            return new Result(false, RejectReason.ATTESTATION_MISSING, null, List.of("attestation=null"));
        }
        if (attestation.statementId() == null || attestation.statementId().isBlank()
                || attestation.artifactDigest() == null
                || attestation.claims() == null
                || attestation.claims().buildSource() == null
                || attestation.claims().artifactId() == null
                || attestation.signature() == null
                || attestation.issuedAt() == null) {
            return new Result(false, RejectReason.ATTESTATION_MALFORMED, attestation,
                    List.of("missing-required-fields"));
        }
        basis.add("statement=" + attestation.statementId());

        if (!expectedArtifactDigest.equals(attestation.artifactDigest())) {
            basis.add("bound-digest=" + attestation.artifactDigest() + " != artifact=" + expectedArtifactDigest);
            return new Result(false, RejectReason.ATTESTATION_NOT_BOUND, attestation, basis);
        }
        basis.add("binding=ok");

        String keyId = attestation.signature().keyId();
        TrustVerdict verdict = trustStore.assess(keyId, attestation.signature().signedAt(), now);
        if (!verdict.trusted()) {
            basis.add("attestation-key " + keyId + " -> " + verdict.reason());
            return new Result(false, verdict.reason(), attestation, basis);
        }

        TrustedKey key = trustStore.get(keyId);
        String payloadDigest = payloadDigest(attestation);
        if (!cryptoService.verifyDigestSignature(key.getPublicKey(), payloadDigest,
                attestation.signature().signatureBase64())) {
            basis.add("payloadDigest=" + payloadDigest);
            return new Result(false, RejectReason.SIGNATURE_INVALID, attestation, basis);
        }
        basis.add("attestation-signature=valid");
        return new Result(true, null, attestation, basis);
    }

    /** 结构化解耦的校验结果。 */
    public record Result(boolean ok, RejectReason reason, Attestation attestation, List<String> basis) {
    }
}
