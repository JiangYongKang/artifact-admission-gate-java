package com.github.highcumontoa.artifactadmissiongatejava.core.batch;

import java.time.Duration;

/** 批量请求的规模与耗时上限。 */
public record BatchLimits(int maxItems, Duration timeBudget, long perItemDelayMillisForTest) {

    public static BatchLimits defaults() {
        return new BatchLimits(50, Duration.ofSeconds(2), 0L);
    }
}
