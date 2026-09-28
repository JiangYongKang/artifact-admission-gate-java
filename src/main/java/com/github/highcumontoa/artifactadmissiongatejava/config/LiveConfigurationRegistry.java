package com.github.highcumontoa.artifactadmissiongatejava.config;

import com.github.highcumontoa.artifactadmissiongatejava.config.ConfigurationSnapshot;
import com.github.highcumontoa.artifactadmissiongatejava.policy.PolicyEngine;
import com.github.highcumontoa.artifactadmissiongatejava.trust.TrustStore;

/**
 * 兼容适配器：直接从（可变）TrustStore/PolicyEngine 构造快照，供既有单元测试装配方式使用。
 * 生产环境使用 {@link GovernanceManager}，变更经其串行化并版本化。
 * 取快照时先锁信任库再锁策略引擎，与治理管理器的锁序一致，杜绝半更新视图与死锁。
 */
public class LiveConfigurationRegistry implements ConfigurationRegistry {

    private final TrustStore trustStore;
    private final PolicyEngine policyEngine;

    public LiveConfigurationRegistry(TrustStore trustStore, PolicyEngine policyEngine) {
        this.trustStore = trustStore;
        this.policyEngine = policyEngine;
    }

    @Override
    public ConfigurationSnapshot currentSnapshot() {
        synchronized (trustStore) {
            synchronized (policyEngine) {
                return new ConfigurationSnapshot(
                        trustStore.version() + policyEngine.version(),
                        trustStore.snapshot(),
                        policyEngine.snapshot(),
                        trustStore.version() + "|" + policyEngine.version());
            }
        }
    }
}
