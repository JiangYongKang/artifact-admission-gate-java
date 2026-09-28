package com.github.highcumontoa.artifactadmissiongatejava.provenance;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 重放防护：记录每条证明（statementId）首次归属的请求哈希。
 *
 * 同一 statementId 再次出现时：
 * - 若就是原请求本身的复核提交，属主一致，走正常的配置复核流程；
 * - 若被挪到别的请求/制品上，属主不一致，直接归到原本那条结论，
 *   既不会产生新的准入记录，也不会凭空放行。
 */
public class ReplayGuard {

    private final ConcurrentHashMap<String, String> ownerByStatementId = new ConcurrentHashMap<>();

    /**
     * 声明证明属主；若该证明已被占用，返回既有属主请求哈希，当前状态不变。
     *
     * @return 该证明最终的属主请求哈希
     */
    public String claim(String statementId, String requestHash) {
        return ownerByStatementId.putIfAbsent(statementId, requestHash) == null
                ? requestHash
                : ownerByStatementId.get(statementId);
    }

    public Optional<String> ownerOf(String statementId) {
        return Optional.ofNullable(ownerByStatementId.get(statementId));
    }
}
