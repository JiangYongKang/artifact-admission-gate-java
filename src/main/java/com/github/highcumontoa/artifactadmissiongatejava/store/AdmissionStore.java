package com.github.highcumontoa.artifactadmissiongatejava.store;

import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionDecision;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRecord;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 线程安全的准入记录存储。
 *
 * 每个请求哈希对应一条“修订链”：首次提交产生 revision=1 的记录；配置（信任根/策略）变化后
 * 同一请求再次提交，若结论发生变化则原子追加 revision+1 的新记录并以 supersedesRecordId 串联；
 * 若结论不变则归并为既有记录（保证重复提交幂等、并发提交只有一条记录）。
 * 每条记录一旦写入即不可变；findByRequestHash 永远返回链上的最新结论。
 */
public class AdmissionStore {

    private final ConcurrentHashMap<String, AdmissionRecord> byId = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> headByRequestHash = new ConcurrentHashMap<>();
    private final Object commitLock = new Object();

    /**
     * 提交一个判定结论：与当前最新结论一致则归并返回既有记录，否则原子追加修订版。
     * 先写记录再发布索引，保证任何读者经索引取到的记录绝不缺失。
     */
    public AdmissionRecord commit(String requestHash, String artifactId, AdmissionDecision decision) {
        synchronized (commitLock) {
            String headId = headByRequestHash.get(requestHash);
            AdmissionRecord head = headId == null ? null : byId.get(headId);
            if (head != null && sameOutcome(head.decision(), decision)) {
                return head;
            }
            int revision = head == null ? 1 : head.revision() + 1;
            String supersedes = head == null ? null : head.recordId();
            AdmissionRecord record = new AdmissionRecord(newRecordId(), requestHash, artifactId,
                    decision.status(), decision, revision, supersedes);
            byId.put(record.recordId(), record);
            headByRequestHash.put(requestHash, record.recordId());
            return record;
        }
    }

    /**
     * 幂等归并判定：仅当两次判定的“判定依据”完全一致时才归并到既有记录。
     * 判定依据 = 结论状态、拒绝原因、生效策略来源、签名密钥。
     * 信任或策略变化后，只要其中任何一项发生变化（例如换用了更高优先级的策略、
     * 签名密钥轮换），即使结论状态相同，也必须另起一条绑定新配置版本的修订记录，
     * 绝不能把旧记录的策略来源与配置版本直接端回。
     * 配置变化若不影响该制品的判定依据（如不匹配该制品的策略、无关密钥），
     * 结论仍是同一条，归并保持幂等。
     */
    private static boolean sameOutcome(AdmissionDecision a, AdmissionDecision b) {
        return a.status() == b.status()
                && a.reason() == b.reason()
                && java.util.Objects.equals(a.policyId(), b.policyId())
                && java.util.Objects.equals(a.signerKeyId(), b.signerKeyId());
    }

    public Optional<AdmissionRecord> findById(String recordId) {
        return Optional.ofNullable(byId.get(recordId));
    }

    /** 返回请求修订链上的最新记录。 */
    public Optional<AdmissionRecord> findByRequestHash(String requestHash) {
        String id = headByRequestHash.get(requestHash);
        return id == null ? Optional.empty() : findById(id);
    }

    public static String newRecordId() {
        return UUID.randomUUID().toString();
    }
}
