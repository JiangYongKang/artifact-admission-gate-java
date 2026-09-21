package com.github.highcumontoa.artifactadmissiongatejava.core.admission;

import com.github.highcumontoa.artifactadmissiongatejava.domain.AdmissionRecord;

import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * 准入记录与重放索引的存储。
 * 同 statementId 的并发提交必须串行化：记录创建、状态迁移、重放计数均原子可见。
 */
public interface AdmissionRepository {

    AdmissionRecord createPending(String admissionId, String artifactDigest, String signerKeyId,
                                  String statementId, String policyId, java.time.Instant now);

    void decide(String admissionId, com.github.highcumontoa.artifactadmissiongatejava.domain.AdmissionStatus status,
                com.github.highcumontoa.artifactadmissiongatejava.domain.RejectReason reason, java.time.Instant now);

    Optional<AdmissionRecord> findById(String admissionId);

    Optional<AdmissionRecord> findByStatement(String statementId);

    /** 在 statementId 维度加锁执行，返回值由回调决定；保证同一证明的并发提交不产生两条记录。 */
    <T> T withStatementLock(String statementId, Function<Optional<AdmissionRecord>, T> action);

    int incrementReplay(String admissionId, java.time.Instant now);

    void remove(String admissionId);

    /** 仅供测试隔离使用：清空全部记录与重放索引。 */
    void clear();

    List<AdmissionRecord> all();
}
