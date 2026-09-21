package com.github.highcumontoa.artifactadmissiongatejava.core;

import java.time.Clock;
import org.springframework.stereotype.Component;

import java.time.Instant;

/** 可替换时钟，便于轮换/过期相关测试确定性复现。 */
@Component
public class TimeSource {

    private volatile Clock clock = Clock.systemUTC();

    public Instant now() { return Instant.now(clock); }

    public void setClock(Clock clock) { this.clock = clock; }
}
