package com.github.highcumontoa.artifactadmissiongatejava.model;

/**
 * 准入提交：制品内容、声明摘要、签名与来源证明（均可来自本地文件）。
 *
 * @param artifactId      制品标识
 * @param declaredDigest  提交方声明的 SHA-256 摘要（十六进制小写）
 * @param contentBase64   制品内容（Base64，模拟制品文件）
 * @param signatureBase64 对 declaredDigest 的签名（Base64，模拟签名文件）
 * @param signerKeyId     签名密钥标识
 * @param provenance      来源证明，可为 null（将被拒绝）
 */
public record AdmissionRequest(
        String artifactId,
        String declaredDigest,
        String contentBase64,
        String signatureBase64,
        String signerKeyId,
        ProvenanceStatement provenance) {
}
