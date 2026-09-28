package com.github.highcumontoa.artifactadmissiongatejava.provenance;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 重放防护：记录每份来源证明的消费归属。
 * 同一 statementId 全局只归属于一条原始准入结论（按 制品标识+摘要 绑定）：
 * - 证明被挪到别的制品上：不产生新记录，结论归到原本那条；
 * - 同一制品按最新配置再次提交：允许重新判定（复核），不视为重放。
 */
public class ReplayGuard {

    /** 一份证明的消费归属。 */
    public record Consumption(String statementId, String artifactId, String artifactDigest,
                              String originalRecordId) {
        public boolean boundTo(String artifactId, String artifactDigest) {
            return this.artifactId.equals(artifactId)
                    && this.artifactDigest.equalsIgnoreCase(artifactDigest);
        }
    }

    private final ConcurrentHashMap<String, Consumption> consumed = new ConcurrentHashMap<>();

    /**
     * 首次消费：登记归属。已存在归属时返回 false 且不覆盖（保留原始结论归属）。
     */
    public boolean tryConsume(String statementId, String artifactId, String artifactDigest,
                              String originalRecordId) {
        return consumed.putIfAbsent(statementId,
                new Consumption(statementId, artifactId, artifactDigest, originalRecordId)) == null;
    }

    public Optional<Consumption> findConsumption(String statementId) {
        return Optional.ofNullable(consumed.get(statementId));
    }
}
