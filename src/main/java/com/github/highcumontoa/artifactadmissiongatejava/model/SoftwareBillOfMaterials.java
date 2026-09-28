package com.github.highcumontoa.artifactadmissiongatejava.model;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 软件成分清单（SBOM，本地文件模拟）：声明某制品包含的组件，必须确实属于该制品。
 *
 * @param billId         清单唯一标识
 * @param artifactId     清单声明所属的制品标识
 * @param artifactDigest 清单声明所属制品的 SHA-256 摘要（十六进制小写）
 * @param components     组件列表
 * @param signerKeyId    清单签名密钥标识
 * @param signature      对规范化载荷的 Ed25519 签名（Base64）
 */
public record SoftwareBillOfMaterials(
        String billId,
        String artifactId,
        String artifactDigest,
        List<SbomComponent> components,
        String signerKeyId,
        String signature) {

    /** 被签名的规范化载荷：绑定 billId/制品标识/摘要/有序组件。 */
    public String canonicalPayload() {
        String componentsPart = components == null ? "" : components.stream()
                .map(c -> c.name() + "@" + c.version())
                .collect(Collectors.joining(","));
        return billId + "|" + artifactId + "|" + artifactDigest + "|" + componentsPart;
    }
}
