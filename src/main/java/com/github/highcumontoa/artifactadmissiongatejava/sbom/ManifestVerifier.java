package com.github.highcumontoa.artifactadmissiongatejava.sbom;

import com.github.highcumontoa.artifactadmissiongatejava.model.ComponentManifest;
import com.github.highcumontoa.artifactadmissiongatejava.model.RejectReason;
import com.github.highcumontoa.artifactadmissiongatejava.policy.TrustPolicy;

/**
 * 软件成分清单校验：归属绑定（制品标识+摘要）与组件范围约束。
 * 两类失败分别给出 {@link RejectReason#SBOM_NOT_BOUND} 与
 * {@link RejectReason#SBOM_COMPONENT_VIOLATION}，绝不笼统地丢一个失败。
 */
public class ManifestVerifier {

    public record Outcome(RejectReason failure, String detail) {
        public boolean isOk() {
            return failure == null;
        }
    }

    /** 校验清单是否绑定到实际提交的制品：清单写的 artifactId 与 digest 都必须对得上。 */
    public Outcome checkBinding(ComponentManifest manifest, String artifactId, String computedDigest) {
        if (!manifest.artifactId().equals(artifactId)) {
            return new Outcome(RejectReason.SBOM_NOT_BOUND,
                    "manifest artifactId=" + manifest.artifactId() + " != submitted artifactId=" + artifactId);
        }
        if (manifest.artifactDigest() == null
                || !manifest.artifactDigest().equalsIgnoreCase(computedDigest)) {
            return new Outcome(RejectReason.SBOM_NOT_BOUND,
                    "manifest digest does not match computed artifact digest; manifest does not belong to this artifact");
        }
        return new Outcome(null, "manifest bound to artifact digest " + computedDigest);
    }

    /** 校验清单中的每个组件是否都落在策略允许的组件名称范围内。 */
    public Outcome checkComponents(ComponentManifest manifest, TrustPolicy policy) {
        if (policy.allowedComponentPatterns() == null) {
            return new Outcome(null, "component range unrestricted by policy " + policy.policyId());
        }
        for (ComponentManifest.Component component : manifest.components()) {
            if (!policy.allowsComponent(component.name())) {
                return new Outcome(RejectReason.SBOM_COMPONENT_VIOLATION,
                        "component " + component.name() + ":" + component.version()
                                + " is outside the allowed component range of policy " + policy.policyId());
            }
        }
        if (policy.allowedComponentPatterns().isEmpty()) {
            return new Outcome(RejectReason.SBOM_COMPONENT_VIOLATION,
                    "policy " + policy.policyId() + " explicitly forbids every component but manifest has "
                            + manifest.components().size() + " component(s)");
        }
        return new Outcome(null,
                manifest.components().size() + " component(s) within range of policy " + policy.policyId());
    }
}
