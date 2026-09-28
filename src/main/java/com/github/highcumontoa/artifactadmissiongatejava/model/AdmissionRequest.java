package com.github.highcumontoa.artifactadmissiongatejava.model;

/**
 * 准入提交：制品内容、声明摘要、签名、来源证明与软件成分清单（均可来自本地文件）。
 *
 * @param artifactId      制品标识
 * @param declaredDigest  提交方声明的 SHA-256 摘要（十六进制小写）
 * @param binding         制品文件与签名绑定
 * @param provenance      来源证明，可为 null（按策略可能被拒绝）
 * @param sbom            软件成分清单，可为 null（按策略可能被拒绝）
 */
public record AdmissionRequest(
        String artifactId,
        String declaredDigest,
        String contentBase64,
        String signatureBase64,
        String signerKeyId,
        ProvenanceStatement provenance,
        SoftwareBillOfMaterials sbom) {

    /** 兼容构造：不含 SBOM 的旧请求。 */
    public AdmissionRequest(String artifactId, String declaredDigest, String contentBase64,
                            String signatureBase64, String signerKeyId, ProvenanceStatement provenance) {
        this(artifactId, declaredDigest, contentBase64, signatureBase64, signerKeyId, provenance, null);
    }
}
