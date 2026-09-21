package com.github.highcumontoa.artifactadmissiongatejava.provenance;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 重放防护：记录已被消费的证明标识。
 * 同一证明重复提交不会产生新结论，也无法绕过已生效的撤销/拒绝。
 */
public class ReplayGuard {

    private final Set<String> consumedStatementIds = ConcurrentHashMap.newKeySet();

    /**
     * 尝试消费一个证明标识。
     *
     * @return true 表示首次提交；false 表示重放
     */
    public boolean tryConsume(String statementId) {
        return consumedStatementIds.add(statementId);
    }

    public boolean isConsumed(String statementId) {
        return consumedStatementIds.contains(statementId);
    }
}
