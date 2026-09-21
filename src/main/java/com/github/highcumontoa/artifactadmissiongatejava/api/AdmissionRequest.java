package com.github.highcumontoa.artifactadmissiongatejava.api;

/** 准入提交请求：以本地文件路径模拟制品、签名、来源证明与 SBOM。 */
public record AdmissionRequest(
        String artifactPath,
        String claimedDigest,
        String signaturePath,
        String attestationPath,
        String sbomPath,
        String policyId
) {
}
