package com.github.highcumontoa.artifactadmissiongatejava.model;

/**
 * 软件成分清单中的单个组件（本地文件模拟）。
 *
 * @param name    组件名称
 * @param version 组件版本
 */
public record SbomComponent(String name, String version) {
}
