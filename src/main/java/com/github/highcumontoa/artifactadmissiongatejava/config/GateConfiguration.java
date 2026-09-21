package com.github.highcumontoa.artifactadmissiongatejava.config;

import com.github.highcumontoa.artifactadmissiongatejava.core.crypto.CryptoService;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyRepository;
import com.github.highcumontoa.artifactadmissiongatejava.core.trust.TrustStore;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** 装配本地信任根、策略库的启动引导（纯内存，离线运行）。 */
@Configuration
@EnableConfigurationProperties(GateProperties.class)
public class GateConfiguration {

    @Bean
    public TrustBootstrap trustBootstrap(GateProperties properties, TrustStore trustStore,
                                         PolicyRepository policyRepository, CryptoService cryptoService) {
        return new TrustBootstrap(properties, trustStore, policyRepository, cryptoService);
    }
}
