package com.github.highcumontoa.artifactadmissiongatejava.config;

import com.github.highcumontoa.artifactadmissiongatejava.policy.PolicyEngine;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ProvenanceVerifier;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ReplayGuard;
import com.github.highcumontoa.artifactadmissiongatejava.sbom.SbomVerifier;
import com.github.highcumontoa.artifactadmissiongatejava.store.AdmissionStore;
import com.github.highcumontoa.artifactadmissiongatejava.trust.TrustStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/** 装配线程安全单例：配置经 GovernanceManager 版本化治理，支撑并发一致性与结论复核。 */
@Configuration
public class AdmissionConfig {

    @Bean
    public AdmissionStore admissionStore() {
        return new AdmissionStore();
    }

    @Bean
    public TrustStore trustStore() {
        return new TrustStore();
    }

    @Bean
    public PolicyEngine policyEngine() {
        return new PolicyEngine();
    }

    @Bean
    public GovernanceManager governanceManager(TrustStore trustStore, PolicyEngine policyEngine) {
        return new GovernanceManager(trustStore, policyEngine);
    }

    @Bean
    public ProvenanceVerifier provenanceVerifier() {
        return new ProvenanceVerifier();
    }

    @Bean
    public SbomVerifier sbomVerifier() {
        return new SbomVerifier();
    }

    @Bean
    public ReplayGuard replayGuard() {
        return new ReplayGuard();
    }

    @Bean
    public Clock admissionClock() {
        return Clock.systemUTC();
    }
}
