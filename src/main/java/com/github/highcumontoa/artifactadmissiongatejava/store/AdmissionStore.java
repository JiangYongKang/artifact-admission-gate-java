package com.github.highcumontoa.artifactadmissiongatejava.store;

import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRecord;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 线程安全的准入记录存储。
 * 以请求规范化哈希做幂等键：同一请求重复提交返回既有记录，绝不产生第二条记录，
 * 因此重放无法绕过已生效的拒绝/撤销结论。结论一旦写入即不可变。
 */
public class AdmissionStore {

    private final ConcurrentHashMap<String, AdmissionRecord> byId = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> recordIdByRequestHash = new ConcurrentHashMap<>();

    /**
     * 幂等写入：若同一请求哈希已有记录，直接返回既有记录。
     * 先写记录再发布索引，保证任何并发读者经索引取到的记录绝不缺失。
     */
    public AdmissionRecord saveIfAbsent(String requestHash, AdmissionRecord record) {
        byId.putIfAbsent(record.recordId(), record);
        String existingId = recordIdByRequestHash.putIfAbsent(requestHash, record.recordId());
        if (existingId != null) {
            return byId.get(existingId);
        }
        return record;
    }

    public Optional<AdmissionRecord> findById(String recordId) {
        return Optional.ofNullable(byId.get(recordId));
    }

    public Optional<AdmissionRecord> findByRequestHash(String requestHash) {
        String id = recordIdByRequestHash.get(requestHash);
        return id == null ? Optional.empty() : findById(id);
    }

    public static String newRecordId() {
        return UUID.randomUUID().toString();
    }
}
