package com.github.highcumontoa.artifactadmissiongatejava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** 准入网关配置项。 */
@ConfigurationProperties(prefix = "admission.gate")
public class GateProperties {

    /** 启动时加载信任根 PEM 的目录（可选）。 */
    private String trustDir = "";
    /** 启动时加载策略 JSON 的目录（可选）。 */
    private String policiesDir = "";
    /** 批量规模上限。 */
    private int batchMaxItems = 50;
    /** 批量耗时上限（毫秒）。 */
    private long batchTimeBudgetMillis = 2000L;

    public String getTrustDir() { return trustDir; }
    public void setTrustDir(String trustDir) { this.trustDir = trustDir; }
    public String getPoliciesDir() { return policiesDir; }
    public void setPoliciesDir(String policiesDir) { this.policiesDir = policiesDir; }
    public int getBatchMaxItems() { return batchMaxItems; }
    public void setBatchMaxItems(int batchMaxItems) { this.batchMaxItems = batchMaxItems; }
    public long getBatchTimeBudgetMillis() { return batchTimeBudgetMillis; }
    public void setBatchTimeBudgetMillis(long batchTimeBudgetMillis) { this.batchTimeBudgetMillis = batchTimeBudgetMillis; }
}
