package com.github.highcumontoa.artifactadmissiongatejava.domain;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 一条准入记录：一旦创建即持久保留，状态在同一把锁下从 PENDING 原子迁移到终态。
 * 任何字段均不含密钥材料（signerKeyId 只是密钥标识符，不是密钥材料本身）。
 */
public final class AdmissionRecord {

    private final String admissionId;
    private volatile AdmissionStatus status;
    private volatile RejectReason rejectReason;
    private final String artifactDigest;
    private volatile String signerKeyId;
    private final String statementId;
    private final String policyId;
    private final Instant createdAt;
    private volatile Instant decidedAt;
    private final List<String> auditTrail;
    private volatile int replayCount;

    public AdmissionRecord(String admissionId, AdmissionStatus status, RejectReason rejectReason,
                           String artifactDigest, String signerKeyId, String statementId,
                           String policyId, Instant createdAt, Instant decidedAt,
                           List<String> auditTrail, int replayCount) {
        this.admissionId = admissionId;
        this.status = status;
        this.rejectReason = rejectReason;
        this.artifactDigest = artifactDigest;
        this.signerKeyId = signerKeyId;
        this.statementId = statementId;
        this.policyId = policyId;
        this.createdAt = createdAt;
        this.decidedAt = decidedAt;
        this.auditTrail = auditTrail != null ? new CopyOnWriteArrayList<>(auditTrail) : new CopyOnWriteArrayList<>();
        this.replayCount = replayCount;
    }

    public String getAdmissionId() { return admissionId; }
    public AdmissionStatus getStatus() { return status; }
    public RejectReason getRejectReason() { return rejectReason; }
    public String getArtifactDigest() { return artifactDigest; }
    public String getSignerKeyId() { return signerKeyId; }
    public String getStatementId() { return statementId; }
    public String getPolicyId() { return policyId; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getDecidedAt() { return decidedAt; }
    public List<String> getAuditTrail() { return List.copyOf(auditTrail); }
    public int getReplayCount() { return replayCount; }

    /** 在持锁状态下迁移到终态并追加判定依据，保证不存在半更新。 */
    public void markTerminal(AdmissionStatus terminal, RejectReason reason, Instant at) {
        if (this.status != AdmissionStatus.PENDING) {
            if (terminal == this.status && reason == this.rejectReason) {
                this.decidedAt = at;
                return;
            }
            throw new IllegalStateException("already-decided:" + admissionId);
        }
        this.status = terminal;
        this.rejectReason = reason;
        this.decidedAt = at;
    }

    /** 重放复核：在持锁路径下把终态更新为当前策略/信任根下的最新结论。 */
    public void reevaluate(AdmissionStatus terminal, RejectReason reason, Instant at, String basis) {
        this.status = terminal;
        this.rejectReason = reason;
        this.decidedAt = at;
        if (basis != null) {
            this.auditTrail.add(at + " replay-reevaluate -> " + terminal + "/" + reason + " : " + basis);
        }
    }

    /** 校验得到签名密钥后补全签名者，仅允许由空值设置一次（持锁调用）。 */
    public void bindSigner(String keyId) {
        if (this.signerKeyId == null) {
            this.signerKeyId = keyId;
        }
    }

    public void addTrail(String entry) {
        this.auditTrail.add(entry);
    }

    public int incrementReplay(Instant at) {
        int next = this.replayCount + 1;
        this.replayCount = next;
        this.auditTrail.add(at + " replay-submission#" + next);
        return next;
    }
}
