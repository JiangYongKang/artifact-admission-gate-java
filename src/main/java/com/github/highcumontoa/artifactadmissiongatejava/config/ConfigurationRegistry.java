package com.github.highcumontoa.artifactadmissiongatejava.config;

/**
 * 配置注册表：准入判定通过它获取当前不可变配置快照。
 * 实现必须保证快照原子可见，读侧永不观察到半更新状态。
 */
public interface ConfigurationRegistry {

    /** 当前最新配置快照（不可变）。 */
    ConfigurationSnapshot currentSnapshot();
}
