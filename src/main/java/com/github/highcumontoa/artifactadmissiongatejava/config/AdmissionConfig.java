package com.github.highcumontoa.artifactadmissiongatejava.config;

import com.github.highcumontoa.artifactadmissiongatejava.policy.PolicyEngine;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ProvenanceVerifier;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ReplayGuard;
import com.github.highcumontoa.artifactadmissiongatejava.store.AdmissionStore;
import com.github.highcumontoa.artifactadmissiongatejava.trust.TrustStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/** 装配线程安全单例：所有组件无共享可变状态，支撑并发一致性。 */
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
    public ProvenanceVerifier provenanceVerifier() {
        return new ProvenanceVerifier();
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
