package com.github.highcumontoa.artifactadmissiongatejava.store;

import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRecord;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 线程安全的准入记录存储。
 * 幂等键为「请求规范化哈希 + 判定所依据的配置版本」：
 * <ul>
 *   <li>同一请求在同一配置版本下重复（含并发）提交：归并为同一条记录；</li>
 *   <li>信任/策略变更后再次提交同一制品：键中版本不同，按最新配置重新判定，
 *       旧记录保留用于追溯，但不会被当成当前结论直接端回。</li>
 * </ul>
 * 先写记录再发布索引，保证任何并发读者经索引取到的记录绝不缺失。结论一旦写入即不可变。
 */
public class AdmissionStore {

    private final ConcurrentHashMap<String, AdmissionRecord> byId = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> recordIdByIdempotencyKey = new ConcurrentHashMap<>();

    /**
     * 幂等写入：若同一幂等键已有记录，直接返回既有记录。
     * 先写记录再发布索引，保证任何并发读者经索引取到的记录绝不缺失。
     */
    public AdmissionRecord saveIfAbsent(String idempotencyKey, AdmissionRecord record) {
        byId.putIfAbsent(record.recordId(), record);
        String existingId = recordIdByIdempotencyKey.putIfAbsent(idempotencyKey, record.recordId());
        if (existingId != null) {
            return byId.get(existingId);
        }
        return record;
    }

    public Optional<AdmissionRecord> findById(String recordId) {
        return Optional.ofNullable(byId.get(recordId));
    }

    public Optional<AdmissionRecord> findByIdempotencyKey(String idempotencyKey) {
        String id = recordIdByIdempotencyKey.get(idempotencyKey);
        return id == null ? Optional.empty() : findById(id);
    }

    public static String newRecordId() {
        return UUID.randomUUID().toString();
    }
}
