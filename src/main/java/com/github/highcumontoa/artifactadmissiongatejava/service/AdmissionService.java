package com.github.highcumontoa.artifactadmissiongatejava.service;

import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionDecision;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRecord;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionStatus;
import com.github.highcumontoa.artifactadmissiongatejava.model.RejectReason;
import com.github.highcumontoa.artifactadmissiongatejava.policy.PolicyDecision;
import com.github.highcumontoa.artifactadmissiongatejava.policy.PolicyEngine;
import com.github.highcumontoa.artifactadmissiongatejava.policy.TrustPolicy;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ProvenanceVerifier;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ReplayGuard;
import com.github.highcumontoa.artifactadmissiongatejava.store.AdmissionStore;
import com.github.highcumontoa.artifactadmissiongatejava.trust.CryptoSupport;
import com.github.highcumontoa.artifactadmissiongatejava.trust.TrustedKey;
import com.github.highcumontoa.artifactadmissiongatejava.trust.TrustStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * 准入校验编排：摘要 → 策略 → 签名 → 证明，按固定顺序判定，拒绝原因可区分。
 * 所有依赖均为线程安全组件，校验过程无共享可变状态，并发下结果一致。
 */
@Service
public class AdmissionService {

    private static final Logger log = LoggerFactory.getLogger(AdmissionService.class);

    private final AdmissionStore store;
    private final TrustStore trustStore;
    private final PolicyEngine policyEngine;
    private final ProvenanceVerifier provenanceVerifier;
    private final ReplayGuard replayGuard;
    private final Clock clock;
    private final int maxBatchSize;
    private final Duration maxBatchDuration;

    public AdmissionService(AdmissionStore store,
                            TrustStore trustStore,
                            PolicyEngine policyEngine,
                            ProvenanceVerifier provenanceVerifier,
                            ReplayGuard replayGuard,
                            Clock clock,
                            @Value("${admission.batch.max-size:100}") int maxBatchSize,
                            @Value("${admission.batch.max-duration-ms:5000}") long maxBatchDurationMs) {
        this.store = store;
        this.trustStore = trustStore;
        this.policyEngine = policyEngine;
        this.provenanceVerifier = provenanceVerifier;
        this.replayGuard = replayGuard;
        this.clock = clock;
        this.maxBatchSize = maxBatchSize;
        this.maxBatchDuration = Duration.ofMillis(maxBatchDurationMs);
    }

    /** 提交单个准入请求：幂等，重复提交返回既有记录。 */
    public AdmissionRecord submit(AdmissionRequest request) {
        String requestHash = hashRequest(request);
        Optional<AdmissionRecord> existing = store.findByRequestHash(requestHash);
        if (existing.isPresent()) {
            log.info("duplicate submission requestHash={} -> existing recordId={} status={}",
                    requestHash, existing.get().recordId(), existing.get().status());
            return existing.get();
        }
        AdmissionDecision decision = verify(request);
        AdmissionRecord record = new AdmissionRecord(
                AdmissionStore.newRecordId(), requestHash, request.artifactId(), decision.status(), decision);
        AdmissionRecord saved = store.saveIfAbsent(requestHash, record);
        log.info("admission decided recordId={} artifactId={} digest={} status={} reason={} detail={}",
                saved.recordId(), saved.artifactId(), decision.computedDigest(),
                saved.status(), decision.reason(), decision.detail());
        return saved;
    }

    /**
     * 批量提交：规模超限整批拒绝（不落任何记录）；耗时超限则剩余项以
     * BATCH_LIMIT_EXCEEDED 明确拒绝，每条记录均为完整终态，无半更新残留。
     */
    public BatchResult submitBatch(List<AdmissionRequest> requests) {
        if (requests.size() > maxBatchSize) {
            log.warn("batch rejected: size={} exceeds maxBatchSize={}", requests.size(), maxBatchSize);
            return BatchResult.rejectedWhole(requests.size(), maxBatchSize);
        }
        Instant deadline = clock.instant().plus(maxBatchDuration);
        List<AdmissionRecord> records = new ArrayList<>(requests.size());
        for (AdmissionRequest request : requests) {
            if (!clock.instant().isBefore(deadline)) {
                AdmissionDecision decision = AdmissionDecision.rejected(
                        RejectReason.BATCH_LIMIT_EXCEEDED,
                        "batch time budget " + maxBatchDuration.toMillis() + "ms exhausted", null, null, null);
                records.add(store.saveIfAbsent(hashRequest(request), new AdmissionRecord(
                        AdmissionStore.newRecordId(), hashRequest(request), request.artifactId(),
                        AdmissionStatus.REJECTED, decision)));
                continue;
            }
            records.add(submit(request));
        }
        return BatchResult.completed(records);
    }

    /** 结论查询：不存在时返回空，由调用方映射为 404，绝不返回中间态。 */
    public Optional<AdmissionRecord> query(String recordId) {
        return store.findById(recordId);
    }

    /** 校验流水线：任一阶段失败即定终态，原因可区分。 */
    private AdmissionDecision verify(AdmissionRequest request) {
        // 1. 摘要校验
        byte[] content;
        try {
            content = Base64.getDecoder().decode(request.contentBase64());
        } catch (IllegalArgumentException e) {
            return AdmissionDecision.rejected(RejectReason.DIGEST_MISMATCH,
                    "content is not valid Base64; digest cannot be reproduced", null, null, request.signerKeyId());
        }
        String computedDigest = CryptoSupport.sha256Hex(content);
        if (!computedDigest.equalsIgnoreCase(request.declaredDigest())) {
            return AdmissionDecision.rejected(RejectReason.DIGEST_MISMATCH,
                    "declared digest does not match computed sha256 of content",
                    computedDigest, null, request.signerKeyId());
        }

        // 2. 策略选择（失败关闭：缺失/冲突/引用未知密钥）
        PolicyDecision policyDecision = policyEngine.selectApplicable(request.artifactId());
        if (!policyDecision.isAllowed()) {
            return AdmissionDecision.rejected(policyDecision.failure(), policyDecision.detail(),
                    computedDigest, null, request.signerKeyId());
        }
        TrustPolicy policy = policyDecision.applicable();
        RejectReason keyRefFailure = policyEngine.checkKeyReferences(policy,
                keyId -> trustStore.find(keyId).isPresent());
        if (keyRefFailure != null) {
            return AdmissionDecision.rejected(keyRefFailure,
                    "policy " + policy.policyId() + " references key absent from trust store",
                    computedDigest, policy.policyId(), request.signerKeyId());
        }
        RejectReason constraintFailure = policyEngine.checkConstraints(policy, request);
        if (constraintFailure != null) {
            return AdmissionDecision.rejected(constraintFailure,
                    "policy " + policy.policyId() + " constraint violated: " + constraintFailure,
                    computedDigest, policy.policyId(), request.signerKeyId());
        }

        // 3. 制品签名校验
        Optional<TrustedKey> signerKey = trustStore.find(request.signerKeyId());
        if (signerKey.isEmpty()) {
            return AdmissionDecision.rejected(RejectReason.UNTRUSTED_KEY,
                    "signer key not in trust store", computedDigest, policy.policyId(), request.signerKeyId());
        }
        TrustedKey key = signerKey.get();
        if (key.isRevoked()) {
            return AdmissionDecision.rejected(RejectReason.KEY_REVOKED,
                    "signer key revoked: " + key.keyId(), computedDigest, policy.policyId(), key.keyId());
        }
        Instant now = clock.instant();
        Instant issuedAt = request.provenance() != null
                ? Instant.ofEpochSecond(request.provenance().issuedAtEpochSeconds()) : now;
        if (!key.usableForSignatureIssuedAt(issuedAt, now)) {
            return AdmissionDecision.rejected(RejectReason.KEY_EXPIRED,
                    "signer key expired or retired before signature issuance: " + key.keyId(),
                    computedDigest, policy.policyId(), key.keyId());
        }
        byte[] artifactSignature;
        try {
            artifactSignature = Base64.getDecoder().decode(request.signatureBase64());
        } catch (IllegalArgumentException e) {
            return AdmissionDecision.rejected(RejectReason.SIGNATURE_INVALID,
                    "signature is not valid Base64", computedDigest, policy.policyId(), key.keyId());
        }
        boolean signatureOk = CryptoSupport.verifyEd25519(key.publicKey(),
                computedDigest.getBytes(StandardCharsets.UTF_8), artifactSignature);
        if (!signatureOk) {
            return AdmissionDecision.rejected(RejectReason.SIGNATURE_INVALID,
                    "artifact signature verification failed under key " + key.keyId(),
                    computedDigest, policy.policyId(), key.keyId());
        }

        // 4. 来源证明校验
        if (request.provenance() == null) {
            if (policy.requireProvenance()) {
                return AdmissionDecision.rejected(RejectReason.PROVENANCE_MISSING,
                        "policy " + policy.policyId() + " requires provenance but none supplied",
                        computedDigest, policy.policyId(), key.keyId());
            }
            return AdmissionDecision.admitted(
                    "digest+signature verified under policy " + policy.policyId(),
                    computedDigest, policy.policyId(), key.keyId());
        }
        ProvenanceVerifier.Outcome binding = provenanceVerifier.checkBinding(
                request.provenance(), request.artifactId(), computedDigest);
        if (!binding.isOk()) {
            return AdmissionDecision.rejected(binding.failure(), binding.detail(),
                    computedDigest, policy.policyId(), key.keyId());
        }
        ProvenanceVerifier.Outcome provSig = provenanceVerifier.checkSignature(
                request.provenance(), trustStore, now);
        if (!provSig.isOk()) {
            return AdmissionDecision.rejected(provSig.failure(), provSig.detail(),
                    computedDigest, policy.policyId(), key.keyId());
        }
        if (!replayGuard.tryConsume(request.provenance().statementId())) {
            return AdmissionDecision.rejected(RejectReason.PROVENANCE_REPLAYED,
                    "provenance statement already consumed: " + request.provenance().statementId(),
                    computedDigest, policy.policyId(), key.keyId());
        }

        return AdmissionDecision.admitted(
                "digest+signature+provenance verified under policy " + policy.policyId(),
                computedDigest, policy.policyId(), key.keyId());
    }

    /** 请求规范化哈希：幂等键，覆盖全部输入字段。 */
    static String hashRequest(AdmissionRequest request) {
        String provenancePart = request.provenance() == null ? "-" : request.provenance().canonicalPayload()
                + "|" + request.provenance().signerKeyId() + "|" + request.provenance().signature();
        return CryptoSupport.sha256Hex(String.join("|",
                request.artifactId(), request.declaredDigest(), request.contentBase64(),
                request.signatureBase64(), request.signerKeyId(), provenancePart));
    }

    /** 批量结果：要么整批拒绝（无任何记录），要么每项都有终态记录。 */
    public record BatchResult(List<AdmissionRecord> records, boolean wholeBatchRejected, String rejectionDetail) {
        static BatchResult rejectedWhole(int size, int max) {
            return new BatchResult(List.of(), true,
                    "batch size " + size + " exceeds limit " + max + "; whole batch rejected, no records created");
        }

        static BatchResult completed(List<AdmissionRecord> records) {
            return new BatchResult(List.copyOf(records), false, null);
        }
    }
}
