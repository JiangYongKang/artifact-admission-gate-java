package com.github.highcumontoa.artifactadmissiongatejava.core.admission;

import com.github.highcumontoa.artifactadmissiongatejava.domain.AdmissionRecord;
import com.github.highcumontoa.artifactadmissiongatejava.domain.AdmissionStatus;
import com.github.highcumontoa.artifactadmissiongatejava.domain.RejectReason;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * 内存准入仓库。
 *
 * 并发正确性：
 * - records：admissionId -> 记录；statementIndex：statementId -> admissionId。
 * - 同一 statementId 的提交通过 per-key 锁串行化（computeIfAbsent 惰性建锁），
 *   回调内部完成“查重 -> 建 PENDING -> 判终态”全过程，杜绝重复记录与结果串号。
 * - 不同 statementId 使用不同锁，保证吞吐。
 */
@Component
public class InMemoryAdmissionRepository implements AdmissionRepository {

    private final Map<String, AdmissionRecord> records = new ConcurrentHashMap<>();
    private final Map<String, String> statementIndex = new ConcurrentHashMap<>();
    private final Map<String, Object> statementLocks = new ConcurrentHashMap<>();

    @Override
    public AdmissionRecord createPending(String admissionId, String artifactDigest, String signerKeyId,
                                         String statementId, String policyId, Instant now) {
        AdmissionRecord record = new AdmissionRecord(
                admissionId, AdmissionStatus.PENDING, null,
                artifactDigest, signerKeyId, statementId, policyId,
                now, null, new ArrayList<>(List.of(now + " created PENDING")), 0);
        records.put(admissionId, record);
        if (statementId != null && !statementId.isBlank()) {
            // 无条件登记，使得即便记录短暂处于 PENDING，重复提交也只会命中同一条记录
            statementIndex.put(statementId, admissionId);
        }
        return record;
    }

    @Override
    public void decide(String admissionId, AdmissionStatus status, RejectReason reason, Instant now) {
        AdmissionRecord record = records.get(admissionId);
        if (record == null) {
            throw new IllegalStateException("record-not-found:" + admissionId);
        }
        synchronized (record) {
            if (record.getStatus() == AdmissionStatus.PENDING) {
                record.markTerminal(status, reason, now);
            }
        }
    }

    @Override
    public Optional<AdmissionRecord> findById(String admissionId) {
        return Optional.ofNullable(records.get(admissionId));
    }

    @Override
    public Optional<AdmissionRecord> findByStatement(String statementId) {
        String id = statementIndex.get(statementId);
        return id == null ? Optional.empty() : Optional.ofNullable(records.get(id));
    }

    @Override
    public <T> T withStatementLock(String statementId, Function<Optional<AdmissionRecord>, T> action) {
        Object lock = statementLocks.computeIfAbsent(statementId, k -> new Object());
        synchronized (lock) {
            java.util.Optional<AdmissionRecord> existing = findByStatement(statementId);
            if (existing.isEmpty()) {
                // 防御：极端情况下索引缺失时，回退扫描同 statement 的既有记录，避免重复建档
                existing = records.values().stream()
                        .filter(r -> statementId.equals(r.getStatementId()))
                        .findAny();
            }
            return action.apply(existing);
        }
    }

    @Override
    public int incrementReplay(String admissionId, Instant now) {
        AdmissionRecord record = records.get(admissionId);
        if (record == null) {
            throw new IllegalStateException("record-not-found:" + admissionId);
        }
        synchronized (record) {
            return record.incrementReplay(now);
        }
    }

    @Override
    public void remove(String admissionId) {
        AdmissionRecord record = records.remove(admissionId);
        if (record != null && record.getStatementId() != null) {
            statementIndex.remove(record.getStatementId(), admissionId);
        }
    }

    @Override
    public void clear() {
        records.clear();
        statementIndex.clear();
    }

    @Override
    public List<AdmissionRecord> all() {
        return new ArrayList<>(records.values());
    }

    public static String newAdmissionId() {
        return UUID.randomUUID().toString();
    }
}
