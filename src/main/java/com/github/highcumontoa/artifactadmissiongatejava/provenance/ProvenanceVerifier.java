package com.github.highcumontoa.artifactadmissiongatejava.provenance;

import com.github.highcumontoa.artifactadmissiongatejava.config.ConfigurationSnapshot;
import com.github.highcumontoa.artifactadmissiongatejava.model.ProvenanceStatement;
import com.github.highcumontoa.artifactadmissiongatejava.model.RejectReason;
import com.github.highcumontoa.artifactadmissiongatejava.trust.CryptoSupport;
import com.github.highcumontoa.artifactadmissiongatejava.trust.TrustedKey;
import com.github.highcumontoa.artifactadmissiongatejava.trust.TrustStore;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.function.Function;

/**
 * 来源证明校验：绑定性（摘要与制品标识）与证明签名可信性。
 * 判定结果仅含原因分类与说明，不含密钥材料。
 */
public class ProvenanceVerifier {

    public record Outcome(RejectReason failure, String detail) {
        public boolean isOk() {
            return failure == null;
        }
    }

    /** 校验证明与制品的绑定关系。 */
    public Outcome checkBinding(ProvenanceStatement provenance, String artifactId, String computedDigest) {
        if (!provenance.artifactId().equals(artifactId)) {
            return new Outcome(RejectReason.PROVENANCE_NOT_BOUND,
                    "provenance artifactId=" + provenance.artifactId() + " != submitted artifactId=" + artifactId);
        }
        if (!provenance.artifactDigest().equalsIgnoreCase(computedDigest)) {
            return new Outcome(RejectReason.PROVENANCE_NOT_BOUND,
                    "provenance digest does not match computed artifact digest");
        }
        return new Outcome(null, "provenance bound to artifact");
    }

    /** 校验证明签名及其密钥在信任库中的状态（可变信任库，兼容旧装配）。 */
    public Outcome checkSignature(ProvenanceStatement provenance, TrustStore trustStore, Instant now) {
        return checkSignature(provenance,
                (Function<String, Optional<TrustedKey>>) trustStore::find, now);
    }

    /** 校验证明签名及其密钥在指定配置快照中的状态（生产路径，保证整次判定配置一致）。 */
    public Outcome checkSignature(ProvenanceStatement provenance, ConfigurationSnapshot snapshot, Instant now) {
        return checkSignature(provenance,
                (Function<String, Optional<TrustedKey>>) keyId ->
                        Optional.ofNullable(snapshot.keys().get(keyId)), now);
    }

    /** 校验证明签名及其密钥状态，密钥来源由 keyLookup 决定（快照或信任库均可）。 */
    public Outcome checkSignature(ProvenanceStatement provenance,
                                  Function<String, Optional<TrustedKey>> keyLookup, Instant now) {
        Optional<TrustedKey> key = keyLookup.apply(provenance.signerKeyId());
        if (key.isEmpty()) {
            return new Outcome(RejectReason.PROVENANCE_UNTRUSTED,
                    "provenance signer key not in trust store: " + provenance.signerKeyId());
        }
        TrustedKey k = key.get();
        if (k.isRevoked()) {
            return new Outcome(RejectReason.KEY_REVOKED, "provenance signer key revoked: " + k.keyId());
        }
        if (!k.usableForSignatureIssuedAt(Instant.ofEpochSecond(provenance.issuedAtEpochSeconds()), now)) {
            return new Outcome(RejectReason.KEY_EXPIRED,
                    "provenance signer key not usable at issuance time: " + k.keyId());
        }
        return doVerify(provenance, k);
    }

    private Outcome doVerify(ProvenanceStatement provenance, TrustedKey k) {
        byte[] signature;
        try {
            signature = Base64.getDecoder().decode(provenance.signature());
        } catch (IllegalArgumentException e) {
            return new Outcome(RejectReason.PROVENANCE_UNTRUSTED, "provenance signature not valid Base64");
        }
        boolean ok = CryptoSupport.verifyEd25519(k.publicKey(),
                provenance.canonicalPayload().getBytes(StandardCharsets.UTF_8), signature);
        if (!ok) {
            return new Outcome(RejectReason.PROVENANCE_UNTRUSTED, "provenance signature verification failed");
        }
        return new Outcome(null, "provenance signature valid under key " + k.keyId());
    }
}
