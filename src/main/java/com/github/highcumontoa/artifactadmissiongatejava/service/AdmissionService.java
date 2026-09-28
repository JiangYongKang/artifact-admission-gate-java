package com.github.highcumontoa.artifactadmissiongatejava.service;

import com.github.highcumontoa.artifactadmissiongatejava.governance.GovernanceRegistry;
import com.github.highcumontoa.artifactadmissiongatejava.governance.GovernanceSnapshot;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionDecision;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRecord;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionStatus;
import com.github.highcumontoa.artifactadmissiongatejava.model.ComponentManifest;
import com.github.highcumontoa.artifactadmissiongatejava.model.RejectReason;
import com.github.highcumontoa.artifactadmissiongatejava.policy.PolicyDecision;
import com.github.highcumontoa.artifactadmissiongatejava.policy.PolicyEngine;
import com.github.highcumontoa.artifactadmissiongatejava.policy.TrustPolicy;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ProvenanceVerifier;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ReplayGuard;
import com.github.highcumontoa.artifactadmissiongatejava.sbom.ManifestVerifier;
import com.github.highcumontoa.artifactadmissiongatejava.store.AdmissionStore;
import com.github.highcumontoa.artifactadmissiongatejava.trust.CryptoSupport;
import com.github.highcumontoa.artifactadmissiongatejava.trust.TrustedKey;
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
import java.util.concurrent.ConcurrentHashMap;

/**
 * 准入校验编排：摘要 → 策略 → 签名 → 证明 → 成分清单，按固定顺序判定，拒绝原因可区分。
 *
 * 关键语义：
 * 1. 每次请求开始时取一次治理快照（信任根+策略统一版本），全程只用该快照，
 *    并发读写配置绝不会出现半旧半新；
 * 2. 同一请求重复提交一律按当前最新配置重新判定，结论变化则追加修订记录，
 *    不会把旧结论直接端回；结论不变则归并为同一条记录（幂等）；
 * 3. 来源证明被挪用到别的请求时归属到原本那条结论，不产生新记录、不凭空放行。
 */
@Service
public class AdmissionService {

    private static final Logger log = LoggerFactory.getLogger(AdmissionService.class);

    private final AdmissionStore store;
    private final GovernanceRegistry governance;
    private final PolicyEngine policyEngine;
    private final ProvenanceVerifier provenanceVerifier;
    private final ManifestVerifier manifestVerifier;
    private final ReplayGuard replayGuard;
    private final Clock clock;
    private final int maxBatchSize;
    private final Duration maxBatchDuration;
    /** 串行化同一 statementId 的“属主声明 + 落库”，消除重放归属的竞态窗口。 */
    private final ConcurrentHashMap<String, Object> provenanceLocks = new ConcurrentHashMap<>();

    public AdmissionService(AdmissionStore store,
                            GovernanceRegistry governance,
                            PolicyEngine policyEngine,
                            ProvenanceVerifier provenanceVerifier,
                            ManifestVerifier manifestVerifier,
                            ReplayGuard replayGuard,
                            Clock clock,
                            @Value("${admission.batch.max-size:100}") int maxBatchSize,
                            @Value("${admission.batch.max-duration-ms:5000}") long maxBatchDurationMs) {
        this.store = store;
        this.governance = governance;
        this.policyEngine = policyEngine;
        this.provenanceVerifier = provenanceVerifier;
        this.manifestVerifier = manifestVerifier;
        this.replayGuard = replayGuard;
        this.clock = clock;
        this.maxBatchSize = maxBatchSize;
        this.maxBatchDuration = Duration.ofMillis(maxBatchDurationMs);
    }

    /**
     * 提交单个准入请求。
     * 始终按当前最新治理配置重新判定（不读取旧结论直接返回）；结论变化产生修订版。
     * 来源证明的 statementId 若已被其他请求占用（无论本请求判定为何），一律归回原结论，
     * 既不产生新记录也不凭空放行。
     */
    public AdmissionRecord submit(AdmissionRequest request) {
        String requestHash = hashRequest(request);
        GovernanceSnapshot snapshot = governance.current();
        AdmissionDecision decision = verify(request, snapshot);

        if (request.provenance() != null) {
            String statementId = request.provenance().statementId();
            Object lock = provenanceLocks.computeIfAbsent(statementId, k -> new Object());
            synchronized (lock) {
                Optional<String> owner = replayGuard.ownerOf(statementId);
                if (owner.isPresent() && !owner.get().equals(requestHash)) {
                    AdmissionRecord original = store.findByRequestHash(owner.get())
                            .orElseThrow(() -> new IllegalStateException("replay owner record missing: " + owner));
                    log.info("provenance statementId={} reused by foreign requestHash={}; attributed to "
                                    + "original recordId={} status={}",
                            statementId, requestHash, original.recordId(), original.status());
                    return original;
                }
                AdmissionRecord saved = persist(request, requestHash, decision, snapshot.version());
                if (decision.status() == AdmissionStatus.ADMITTED) {
                    // 首次被合法消费：登记属主（同一 statementId 的所有路径都经同一把锁，无竞态）
                    replayGuard.claim(statementId, requestHash);
                }
                return saved;
            }
        }
        return persist(request, requestHash, decision, snapshot.version());
    }

    private AdmissionRecord persist(AdmissionRequest request, String requestHash,
                                    AdmissionDecision decision, long configVersion) {
        AdmissionRecord saved = store.commit(requestHash, request.artifactId(), decision);
        log.info("admission decided recordId={} revision={} supersedes={} artifactId={} digest={} status={} "
                        + "reason={} configVersion={} basis={}",
                saved.recordId(), saved.revision(), saved.supersedesRecordId(), saved.artifactId(),
                decision.computedDigest(), saved.status(), decision.reason(), configVersion, decision.detail());
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
                GovernanceSnapshot snapshot = governance.current();
                AdmissionDecision decision = AdmissionDecision.rejected(
                        RejectReason.BATCH_LIMIT_EXCEEDED,
                        "batch time budget " + maxBatchDuration.toMillis() + "ms exhausted",
                        null, null, null, snapshot.version());
                records.add(store.commit(hashRequest(request), request.artifactId(), decision));
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

    /** 校验流水线：任一阶段失败即定终态，原因可区分；全程基于同一治理快照。 */
    private AdmissionDecision verify(AdmissionRequest request, GovernanceSnapshot snapshot) {
        long version = snapshot.version();

        // 1. 摘要校验
        byte[] content;
        try {
            content = Base64.getDecoder().decode(request.contentBase64());
        } catch (IllegalArgumentException e) {
            return AdmissionDecision.rejected(RejectReason.DIGEST_MISMATCH,
                    "content is not valid Base64; digest cannot be reproduced", null, null,
                    request.signerKeyId(), version);
        }
        String computedDigest = CryptoSupport.sha256Hex(content);
        if (!computedDigest.equalsIgnoreCase(request.declaredDigest())) {
            return AdmissionDecision.rejected(RejectReason.DIGEST_MISMATCH,
                    "declared digest does not match computed sha256 of content",
                    computedDigest, null, request.signerKeyId(), version);
        }

        // 2. 策略选择（失败关闭：缺失/冲突/引用未知密钥）
        PolicyDecision policyDecision = policyEngine.selectApplicable(snapshot.policies(), request.artifactId());
        if (!policyDecision.isAllowed()) {
            return AdmissionDecision.rejected(policyDecision.failure(), policyDecision.detail(),
                    computedDigest, null, request.signerKeyId(), version);
        }
        TrustPolicy policy = policyDecision.applicable();
        RejectReason keyRefFailure = policyEngine.checkKeyReferences(policy, snapshot.keys()::containsKey);
        if (keyRefFailure != null) {
            return AdmissionDecision.rejected(keyRefFailure,
                    "policy " + policy.policyId() + " references key absent from trust store",
                    computedDigest, policy.policyId(), request.signerKeyId(), version);
        }
        RejectReason constraintFailure = policyEngine.checkConstraints(policy, request);
        if (constraintFailure != null) {
            return AdmissionDecision.rejected(constraintFailure,
                    "policy " + policy.policyId() + " constraint violated: " + constraintFailure,
                    computedDigest, policy.policyId(), request.signerKeyId(), version);
        }

        // 3. 制品签名校验
        Optional<TrustedKey> signerKey = snapshot.findKey(request.signerKeyId());
        if (signerKey.isEmpty()) {
            return AdmissionDecision.rejected(RejectReason.UNTRUSTED_KEY,
                    "signer key not in trust store", computedDigest, policy.policyId(),
                    request.signerKeyId(), version);
        }
        TrustedKey key = signerKey.get();
        if (key.isRevoked()) {
            return AdmissionDecision.rejected(RejectReason.KEY_REVOKED,
                    "signer key revoked: " + key.keyId(), computedDigest, policy.policyId(),
                    key.keyId(), version);
        }
        Instant now = clock.instant();
        Instant issuedAt = request.provenance() != null
                ? Instant.ofEpochSecond(request.provenance().issuedAtEpochSeconds()) : now;
        if (!key.usableForSignatureIssuedAt(issuedAt, now)) {
            return AdmissionDecision.rejected(RejectReason.KEY_EXPIRED,
                    "signer key expired or retired before signature issuance: " + key.keyId(),
                    computedDigest, policy.policyId(), key.keyId(), version);
        }
        byte[] artifactSignature;
        try {
            artifactSignature = Base64.getDecoder().decode(request.signatureBase64());
        } catch (IllegalArgumentException e) {
            return AdmissionDecision.rejected(RejectReason.SIGNATURE_INVALID,
                    "signature is not valid Base64", computedDigest, policy.policyId(),
                    key.keyId(), version);
        }
        boolean signatureOk = CryptoSupport.verifyEd25519(key.publicKey(),
                computedDigest.getBytes(StandardCharsets.UTF_8), artifactSignature);
        if (!signatureOk) {
            return AdmissionDecision.rejected(RejectReason.SIGNATURE_INVALID,
                    "artifact signature verification failed under key " + key.keyId(),
                    computedDigest, policy.policyId(), key.keyId(), version);
        }

        // 4. 来源证明校验
        if (request.provenance() == null) {
            if (policy.requireProvenance()) {
                return AdmissionDecision.rejected(RejectReason.PROVENANCE_MISSING,
                        "policy " + policy.policyId() + " requires provenance but none supplied",
                        computedDigest, policy.policyId(), key.keyId(), version);
            }
        } else {
            ProvenanceVerifier.Outcome binding = provenanceVerifier.checkBinding(
                    request.provenance(), request.artifactId(), computedDigest);
            if (!binding.isOk()) {
                return AdmissionDecision.rejected(binding.failure(), binding.detail(),
                        computedDigest, policy.policyId(), key.keyId(), version);
            }
            ProvenanceVerifier.Outcome provSig = provenanceVerifier.checkSignature(
                    request.provenance(), snapshot, now);
            if (!provSig.isOk()) {
                return AdmissionDecision.rejected(provSig.failure(), provSig.detail(),
                        computedDigest, policy.policyId(), key.keyId(), version);
            }
        }

        // 5. 软件成分清单校验（放行前必须确认清单确实属于这份制品）
        ComponentManifest manifest = request.manifest();
        if (manifest == null) {
            if (policy.requireManifest()) {
                return AdmissionDecision.rejected(RejectReason.SBOM_MISSING,
                        "policy " + policy.policyId() + " requires a component manifest but none supplied",
                        computedDigest, policy.policyId(), key.keyId(), version);
            }
        } else {
            ManifestVerifier.Outcome sbomBinding =
                    manifestVerifier.checkBinding(manifest, request.artifactId(), computedDigest);
            if (!sbomBinding.isOk()) {
                return AdmissionDecision.rejected(sbomBinding.failure(), sbomBinding.detail(),
                        computedDigest, policy.policyId(), key.keyId(), version);
            }
            ManifestVerifier.Outcome components = manifestVerifier.checkComponents(manifest, policy);
            if (!components.isOk()) {
                return AdmissionDecision.rejected(components.failure(), components.detail(),
                        computedDigest, policy.policyId(), key.keyId(), version);
            }
        }

        String verified = request.provenance() == null ? "digest+signature" : "digest+signature+provenance";
        if (manifest != null) {
            verified += "+manifest";
        }
        return AdmissionDecision.admitted(
                verified + " verified under policy " + policy.policyId() + " at configVersion " + version,
                computedDigest, policy.policyId(), key.keyId(), version);
    }

    /** 请求规范化哈希：幂等键，覆盖全部输入字段（含成分清单）。 */
    public static String hashRequest(AdmissionRequest request) {
        String provenancePart = request.provenance() == null ? "-" : request.provenance().canonicalPayload()
                + "|" + request.provenance().signerKeyId() + "|" + request.provenance().signature();
        String manifestPart = request.manifest() == null ? "-" : canonicalManifest(request.manifest());
        return CryptoSupport.sha256Hex(String.join("|",
                request.artifactId(), request.declaredDigest(), request.contentBase64(),
                request.signatureBase64(), request.signerKeyId(), provenancePart, manifestPart));
    }

    private static String canonicalManifest(ComponentManifest manifest) {
        List<String> parts = new ArrayList<>();
        for (ComponentManifest.Component c : manifest.components()) {
            parts.add(c.name() + "=" + c.version());
        }
        return String.join("|", manifest.manifestId(), manifest.artifactId(),
                manifest.artifactDigest(), String.join(",", parts));
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
