package com.github.highcumontoa.artifactadmissiongatejava.config;

import com.github.highcumontoa.artifactadmissiongatejava.governance.GovernanceRegistry;
import com.github.highcumontoa.artifactadmissiongatejava.policy.PolicyEngine;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ProvenanceVerifier;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ReplayGuard;
import com.github.highcumontoa.artifactadmissiongatejava.sbom.ManifestVerifier;
import com.github.highcumontoa.artifactadmissiongatejava.store.AdmissionStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/** 装配线程安全单例：治理状态原子发布、组件无共享可变状态，支撑运行期治理与并发一致。 */
@Configuration
public class AdmissionConfig {

    @Bean
    public AdmissionStore admissionStore() {
        return new AdmissionStore();
    }

    @Bean
    public GovernanceRegistry governanceRegistry() {
        return new GovernanceRegistry();
    }

    @Bean
    public PolicyEngine policyEngine() {
        return new PolicyEngine();
    }

    @Bean
    public ProvenanceVerifier provenanceVerifier() {
        return new ProvenanceVerifier();
    }

    @Bean
    public ManifestVerifier manifestVerifier() {
        return new ManifestVerifier();
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
