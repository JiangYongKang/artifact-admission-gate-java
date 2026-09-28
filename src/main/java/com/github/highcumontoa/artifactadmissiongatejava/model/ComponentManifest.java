package com.github.highcumontoa.artifactadmissiongatejava.model;

import java.util.List;

/**
 * 软件成分清单（本地文件模拟的 SBOM）：声明制品包含哪些软件组件。
 *
 * @param manifestId     清单标识
 * @param artifactId     清单所声明归属的制品标识（必须与提交制品一致）
 * @param artifactDigest 清单所声明归属的制品 SHA-256 摘要（必须与实际制品摘要一致）
 * @param components     组件条目
 */
public record ComponentManifest(
        String manifestId,
        String artifactId,
        String artifactDigest,
        List<Component> components) {

    /** 软件组件条目：名称与版本。 */
    public record Component(String name, String version) {
    }
}
