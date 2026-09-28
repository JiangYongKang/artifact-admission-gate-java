package com.github.highcumontoa.artifactadmissiongatejava.sbom;

import com.github.highcumontoa.artifactadmissiongatejava.model.RejectReason;
import com.github.highcumontoa.artifactadmissiongatejava.model.SbomComponent;
import com.github.highcumontoa.artifactadmissiongatejava.model.SoftwareBillOfMaterials;
import com.github.highcumontoa.artifactadmissiongatejava.policy.TrustPolicy;
import com.github.highcumontoa.artifactadmissiongatejava.trust.CryptoSupport;
import com.github.highcumontoa.artifactadmissiongatejava.trust.TrustedKey;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * 软件成分清单校验：绑定性（清单必须确实属于该制品）、签名可信性、成分合规性。
 * 三类失败分别给出 SBOM_NOT_BOUND / SBOM_UNTRUSTED / SBOM_COMPONENT_NOT_ALLOWED，
 * 绝不笼统合并。结论仅含原因分类与说明，不含密钥材料。
 */
public class SbomVerifier {

    public record Outcome(RejectReason failure, String detail) {
        public boolean isOk() {
            return failure == null;
        }
    }

    /** 绑定校验：清单内 artifactId 与摘要必须与实际提交制品完全一致。 */
    public Outcome checkBinding(SoftwareBillOfMaterials sbom, String artifactId, String computedDigest) {
        if (!sbom.artifactId().equals(artifactId)) {
            return new Outcome(RejectReason.SBOM_NOT_BOUND,
                    "sbom artifactId=" + sbom.artifactId() + " != submitted artifactId=" + artifactId);
        }
        if (!sbom.artifactDigest().equalsIgnoreCase(computedDigest)) {
            return new Outcome(RejectReason.SBOM_NOT_BOUND,
                    "sbom digest does not match computed artifact digest");
        }
        return new Outcome(null, "sbom bound to artifact");
    }

    /**
     * 签名与密钥状态校验。
     *
     * @param keyLookup 按 keyId 在当前配置快照中查密钥
     */
    public Outcome checkSignature(SoftwareBillOfMaterials sbom, Function<String, Optional<TrustedKey>> keyLookup,
                                  Instant now) {
        Optional<TrustedKey> found = keyLookup.apply(sbom.signerKeyId());
        if (found.isEmpty()) {
            return new Outcome(RejectReason.SBOM_UNTRUSTED,
                    "sbom signer key not in trust store: " + sbom.signerKeyId());
        }
        TrustedKey key = found.get();
        if (key.isRevoked()) {
            return new Outcome(RejectReason.KEY_REVOKED, "sbom signer key revoked: " + key.keyId());
        }
        if (key.isExpiredAt(now)) {
            return new Outcome(RejectReason.KEY_EXPIRED, "sbom signer key expired: " + key.keyId());
        }
        byte[] signature;
        try {
            signature = Base64.getDecoder().decode(sbom.signature());
        } catch (IllegalArgumentException e) {
            return new Outcome(RejectReason.SBOM_UNTRUSTED, "sbom signature is not valid Base64");
        }
        boolean ok = CryptoSupport.verifyEd25519(key.publicKey(),
                sbom.canonicalPayload().getBytes(StandardCharsets.UTF_8), signature);
        if (!ok) {
            return new Outcome(RejectReason.SBOM_UNTRUSTED, "sbom signature verification failed");
        }
        return new Outcome(null, "sbom signature valid under key " + key.keyId());
    }

    /** 成分合规：清单组件必须落在策略允许范围内；任一越界即拒绝。 */
    public Outcome checkComponents(TrustPolicy policy, List<SbomComponent> components) {
        if (policy.allowedComponents() == null) {
            return new Outcome(null, "components unrestricted by policy " + policy.policyId());
        }
        for (SbomComponent component : components) {
            if (!policy.allowsComponent(component.name(), component.version())) {
                return new Outcome(RejectReason.SBOM_COMPONENT_NOT_ALLOWED,
                        "component " + component.name() + "@" + component.version()
                                + " not within allowed component scope of policy " + policy.policyId());
            }
        }
        return new Outcome(null, "components within policy scope");
    }
}
