package com.github.highcumontoa.artifactadmissiongatejava.service;

import com.github.highcumontoa.artifactadmissiongatejava.config.ConfigurationRegistry;
import com.github.highcumontoa.artifactadmissiongatejava.config.ConfigurationSnapshot;
import com.github.highcumontoa.artifactadmissiongatejava.config.LiveConfigurationRegistry;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionDecision;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRecord;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.model.AdmissionStatus;
import com.github.highcumontoa.artifactadmissiongatejava.model.ProvenanceStatement;
import com.github.highcumontoa.artifactadmissiongatejava.model.RejectReason;
import com.github.highcumontoa.artifactadmissiongatejava.model.SbomComponent;
import com.github.highcumontoa.artifactadmissiongatejava.model.SoftwareBillOfMaterials;
import com.github.highcumontoa.artifactadmissiongatejava.policy.PolicyDecision;
import com.github.highcumontoa.artifactadmissiongatejava.policy.PolicyEngine;
import com.github.highcumontoa.artifactadmissiongatejava.policy.TrustPolicy;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ProvenanceVerifier;
import com.github.highcumontoa.artifactadmissiongatejava.provenance.ReplayGuard;
import com.github.highcumontoa.artifactadmissiongatejava.sbom.SbomVerifier;
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
 * 准入校验编排：摘要 → 策略 → 制品签名 → 来源证明 → 软件成分清单，按固定顺序判定。
 *
 * <p>一次请求在入口固定一份 {@link ConfigurationSnapshot}，随后全部阶段只读该快照，
 * 因此并发的配置读写不会让某次请求一半旧配置一半新配置；不同请求在同一版本快照下
 * 结论必然一致。幂等键含配置版本，信任/策略变更后同一制品按最新状态重新判定。
 */
@Service
public class AdmissionService {

    private static final Logger log = LoggerFactory.getLogger(AdmissionService.class);

    private final AdmissionStore store;
    private final ConfigurationRegistry configurations;
    private final TrustStore trustStore;
    private final PolicyEngine policyEngine;
    private final ProvenanceVerifier provenanceVerifier;
    private final SbomVerifier sbomVerifier;
    private final ReplayGuard replayGuard;
    private final Clock clock;
    private final int maxBatchSize;
    private final Duration maxBatchDuration;

    /** 生产装配：配置由版本化治理注册表提供，一次判定固定使用同一快照。 */
    @org.springframework.beans.factory.annotation.Autowired
    public AdmissionService(AdmissionStore store,
                            ConfigurationRegistry configurations,
                            TrustStore trustStore,
                            PolicyEngine policyEngine,
                            ProvenanceVerifier provenanceVerifier,
                            SbomVerifier sbomVerifier,
                            ReplayGuard replayGuard,
                            Clock clock,
                            @Value("${admission.batch.max-size:100}") int maxBatchSize,
                            @Value("${admission.batch.max-duration-ms:5000}") long maxBatchDurationMs) {
        this.store = store;
        this.configurations = configurations;
        this.trustStore = trustStore;
        this.policyEngine = policyEngine;
        this.provenanceVerifier = provenanceVerifier;
        this.sbomVerifier = sbomVerifier;
        this.replayGuard = replayGuard;
        this.clock = clock;
        this.maxBatchSize = maxBatchSize;
        this.maxBatchDuration = Duration.ofMillis(maxBatchDurationMs);
    }

    /** 兼容构造：既有测试直接持有可变 TrustStore/PolicyEngine 的装配方式。 */
    public AdmissionService(AdmissionStore store,
                            TrustStore trustStore,
                            PolicyEngine policyEngine,
                            ProvenanceVerifier provenanceVerifier,
                            ReplayGuard replayGuard,
                            Clock clock,
                            int maxBatchSize,
                            long maxBatchDurationMs) {
        this(store, new LiveConfigurationRegistry(trustStore, policyEngine), trustStore, policyEngine,
                provenanceVerifier, new SbomVerifier(), replayGuard, clock, maxBatchSize, maxBatchDurationMs);
    }

    /** 提交单个准入请求：幂等，重复提交返回同一配置版本下的既有记录。 */
    public AdmissionRecord submit(AdmissionRequest request) {
        ConfigurationSnapshot snapshot = configurations.currentSnapshot();
        String requestHash = hashRequest(request);
        String idempotencyKey = idempotencyKey(requestHash, snapshot.version());
        Optional<AdmissionRecord> existing = store.findByIdempotencyKey(idempotencyKey);
        if (existing.isPresent()) {
            log.info("duplicate submission requestHash={} configVersion={} -> existing recordId={} status={}",
                    requestHash, snapshot.version(), existing.get().recordId(), existing.get().status());
            return existing.get();
        }
        AdmissionResult verified = verify(request, snapshot);
        if (verified.attributedRecordId() != null) {
            // 证明被挪用：返回非持久化的归属视图（不占新记录、不进幂等索引），指向原本那条结论。
            AdmissionRecord view = new AdmissionRecord(
                    "attribution:" + verified.attributedRecordId(), requestHash, request.artifactId(),
                    verified.decision().status(), verified.decision(), null, verified.attributedRecordId());
            log.info("provenance attribution view artifactId={} digest={} reason={} attributedRecordId={} basis={}",
                    request.artifactId(), verified.decision().computedDigest(),
                    verified.decision().reason(), verified.attributedRecordId(), verified.decision().detail());
            return view;
        }
        AdmissionDecision decision = verified.decision();
        AdmissionRecord record = new AdmissionRecord(
                AdmissionStore.newRecordId(), requestHash, request.artifactId(),
                decision.status(), decision, snapshot.versionToken(), null);
        AdmissionRecord saved = store.saveIfAbsent(idempotencyKey, record);
        if (saved == record && decision.status() == AdmissionStatus.ADMITTED
                && request.provenance() != null) {
            // 仅放行结论才消费证明；保留原始归属，重复登记不覆盖（并发下第一个胜出）。
            replayGuard.tryConsume(request.provenance().statementId(),
                    request.provenance().artifactId(), request.provenance().artifactDigest(),
                    saved.recordId());
        }
        log.info("admission decided recordId={} artifactId={} digest={} status={} reason={} configVersion={} basis={}",
                saved.recordId(), saved.artifactId(), decision.computedDigest(),
                saved.status(), decision.reason(), snapshot.version(), decision.detail());
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
                ConfigurationSnapshot snapshot = configurations.currentSnapshot();
                records.add(store.saveIfAbsent(idempotencyKey(hashRequest(request), snapshot.version()),
                        new AdmissionRecord(
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

    /** 校验流水线：任一阶段失败即定终态，原因可区分；全程只读同一份配置快照。 */
    private AdmissionResult verify(AdmissionRequest request, ConfigurationSnapshot snapshot) {
        String cv = snapshot.versionToken();

        // 1. 摘要校验
        byte[] content;
        try {
            content = Base64.getDecoder().decode(request.contentBase64());
        } catch (IllegalArgumentException e) {
            return reject(AdmissionDecision.rejected(RejectReason.DIGEST_MISMATCH,
                    "content is not valid Base64; digest cannot be reproduced", null, null,
                    request.signerKeyId(), cv));
        }
        String computedDigest = CryptoSupport.sha256Hex(content);
        if (!computedDigest.equalsIgnoreCase(request.declaredDigest())) {
            return reject(AdmissionDecision.rejected(RejectReason.DIGEST_MISMATCH,
                    "declared digest does not match computed sha256 of content",
                    computedDigest, null, request.signerKeyId(), cv));
        }

        // 2. 策略选择（失败关闭：缺失/冲突/引用不受信任密钥）——基于快照中的策略
        PolicyDecision policyDecision = selectApplicable(snapshot, request.artifactId());
        if (!policyDecision.isAllowed()) {
            return reject(AdmissionDecision.rejected(policyDecision.failure(), policyDecision.detail(),
                    computedDigest, null, request.signerKeyId(), cv));
        }
        TrustPolicy policy = policyDecision.applicable();
        RejectReason keyRefFailure = checkKeyReferences(policy, snapshot);
        if (keyRefFailure != null) {
            return reject(AdmissionDecision.rejected(keyRefFailure,
                    "policy " + policy.policyId() + " references key absent or untrusted in current config",
                    computedDigest, policy.policyId(), request.signerKeyId(), cv));
        }
        RejectReason constraintFailure = policyEngine.checkConstraints(policy, request);
        if (constraintFailure != null) {
            return reject(AdmissionDecision.rejected(constraintFailure,
                    "policy " + policy.policyId() + " constraint violated: " + constraintFailure,
                    computedDigest, policy.policyId(), request.signerKeyId(), cv));
        }

        // 3. 制品签名校验（密钥状态以当前快照为准——撤销/过期后复核立即翻转结论）
        TrustedKey key = snapshot.keys().get(request.signerKeyId());
        if (key == null) {
            return reject(AdmissionDecision.rejected(RejectReason.UNTRUSTED_KEY,
                    "signer key not in trust store", computedDigest, policy.policyId(),
                    request.signerKeyId(), cv));
        }
        if (key.isRevoked()) {
            return reject(AdmissionDecision.rejected(RejectReason.KEY_REVOKED,
                    "signer key revoked: " + key.keyId(), computedDigest, policy.policyId(), key.keyId(), cv));
        }
        Instant now = clock.instant();
        Instant issuedAt = request.provenance() != null
                ? Instant.ofEpochSecond(request.provenance().issuedAtEpochSeconds()) : now;
        if (!key.usableForSignatureIssuedAt(issuedAt, now)) {
            return reject(AdmissionDecision.rejected(RejectReason.KEY_EXPIRED,
                    "signer key expired or retired before signature issuance: " + key.keyId(),
                    computedDigest, policy.policyId(), key.keyId(), cv));
        }
        byte[] artifactSignature;
        try {
            artifactSignature = Base64.getDecoder().decode(request.signatureBase64());
        } catch (IllegalArgumentException e) {
            return reject(AdmissionDecision.rejected(RejectReason.SIGNATURE_INVALID,
                    "signature is not valid Base64", computedDigest, policy.policyId(), key.keyId(), cv));
        }
        boolean signatureOk = CryptoSupport.verifyEd25519(key.publicKey(),
                computedDigest.getBytes(StandardCharsets.UTF_8), artifactSignature);
        if (!signatureOk) {
            return reject(AdmissionDecision.rejected(RejectReason.SIGNATURE_INVALID,
                    "artifact signature verification failed under key " + key.keyId(),
                    computedDigest, policy.policyId(), key.keyId(), cv));
        }

        // 4. 来源证明：先绑定，再看是否挪用自别的制品（归属原结论，不产生新记录），再验签
        ProvenanceStatement provenance = request.provenance();
        if (provenance == null) {
            if (policy.requireProvenance()) {
                return reject(AdmissionDecision.rejected(RejectReason.PROVENANCE_MISSING,
                        "policy " + policy.policyId() + " requires provenance but none supplied",
                        computedDigest, policy.policyId(), key.keyId(), cv));
            }
        } else {
            ProvenanceVerifier.Outcome binding =
                    provenanceVerifier.checkBinding(provenance, request.artifactId(), computedDigest);
            if (!binding.isOk()) {
                return reject(AdmissionDecision.rejected(binding.failure(), binding.detail(),
                        computedDigest, policy.policyId(), key.keyId(), cv));
            }
            Optional<ReplayGuard.Consumption> consumed =
                    replayGuard.findConsumption(provenance.statementId());
            if (consumed.isPresent() && !consumed.get().boundTo(request.artifactId(), computedDigest)) {
                // 证明被挪到别的制品：拒绝并归到原本那条结论，绝不凭空产生新的准入记录。
                ReplayGuard.Consumption origin = consumed.get();
                AdmissionDecision decision = AdmissionDecision.rejected(RejectReason.PROVENANCE_REPLAYED,
                        "provenance " + provenance.statementId() + " already belongs to artifact "
                                + origin.artifactId() + " (" + origin.artifactDigest()
                                + "); moved statement is not admissible here",
                        computedDigest, policy.policyId(), key.keyId(), cv);
                return new AdmissionResult(decision, origin.originalRecordId());
            }
            ProvenanceVerifier.Outcome provSig = provenanceVerifier.checkSignature(provenance, snapshot, now);
            if (!provSig.isOk()) {
                return reject(AdmissionDecision.rejected(provSig.failure(), provSig.detail(),
                        computedDigest, policy.policyId(), key.keyId(), cv));
            }
            if (consumed.isPresent()) {
                // 同一制品、同一证明再次提交：不是重放，继续按当前最新配置复核（可能在此前已通过绑定/验签）。
                log.info("provenance {} resubmitted against its own artifact; re-evaluating under config {}",
                        provenance.statementId(), cv);
            }
        }

        // 5. 软件成分清单：策略可强制要求，也可限定组件范围；清单必须确实属于该制品
        SoftwareBillOfMaterials sbom = request.sbom();
        if (sbom == null) {
            if (policy.requireSbom()) {
                return reject(AdmissionDecision.rejected(RejectReason.SBOM_MISSING,
                        "policy " + policy.policyId() + " requires software bill of materials but none supplied",
                        computedDigest, policy.policyId(), key.keyId(), cv));
            }
        } else {
            SbomVerifier.Outcome sbomBinding =
                    sbomVerifier.checkBinding(sbom, request.artifactId(), computedDigest);
            if (!sbomBinding.isOk()) {
                return reject(AdmissionDecision.rejected(sbomBinding.failure(), sbomBinding.detail(),
                        computedDigest, policy.policyId(), key.keyId(), cv));
            }
            if (!policy.allowsSbomSigner(sbom.signerKeyId())) {
                return reject(AdmissionDecision.rejected(RejectReason.SBOM_UNTRUSTED,
                        "sbom signer " + sbom.signerKeyId()
                                + " not in policy " + policy.policyId() + " allowed sbom signers",
                        computedDigest, policy.policyId(), key.keyId(), cv));
            }
            SbomVerifier.Outcome sbomSig = sbomVerifier.checkSignature(
                    sbom, keyId -> Optional.ofNullable(snapshot.keys().get(keyId)), now);
            if (!sbomSig.isOk()) {
                return reject(AdmissionDecision.rejected(sbomSig.failure(), sbomSig.detail(),
                        computedDigest, policy.policyId(), key.keyId(), cv));
            }
            List<SbomComponent> components = sbom.components() == null ? List.of() : sbom.components();
            SbomVerifier.Outcome componentScope = sbomVerifier.checkComponents(policy, components);
            if (!componentScope.isOk()) {
                return reject(AdmissionDecision.rejected(componentScope.failure(), componentScope.detail(),
                        computedDigest, policy.policyId(), key.keyId(), cv));
            }
        }

        String basis = provenance == null
                ? (sbom == null
                        ? "digest+signature verified under policy " + policy.policyId()
                        : "digest+signature+sbom verified under policy " + policy.policyId())
                : (sbom == null
                        ? "digest+signature+provenance verified under policy " + policy.policyId()
                        : "digest+signature+provenance+sbom verified under policy " + policy.policyId());
        return new AdmissionResult(
                AdmissionDecision.admitted(basis, computedDigest, policy.policyId(), key.keyId(), cv), null);
    }

    private static AdmissionResult reject(AdmissionDecision decision) {
        return new AdmissionResult(decision, null);
    }

    /** 内部判定结果：结论 + 可选的归属记录标识（证明挪用时指向原始结论）。 */
    private record AdmissionResult(AdmissionDecision decision, String attributedRecordId) {
    }

    /** 基于快照挑选策略；快照不可变，挑选过程不依赖可变引擎状态。 */
    private PolicyDecision selectApplicable(ConfigurationSnapshot snapshot, String artifactId) {
        List<TrustPolicy> current = snapshot.policies();
        if (current.isEmpty()) {
            return PolicyDecision.fail(RejectReason.POLICY_MISSING, "no trust policy configured; failing closed");
        }
        List<TrustPolicy> matching = current.stream()
                .filter(p -> p.matchesArtifact(artifactId))
                .sorted(java.util.Comparator.comparingInt(TrustPolicy::priority))
                .toList();
        if (matching.isEmpty()) {
            return PolicyDecision.fail(RejectReason.POLICY_MISSING,
                    "no policy matches artifactId=" + artifactId + "; failing closed");
        }
        int best = matching.get(0).priority();
        List<TrustPolicy> top = matching.stream().filter(p -> p.priority() == best).toList();
        if (top.size() > 1) {
            return PolicyDecision.fail(RejectReason.POLICY_CONFLICT,
                    "multiple policies at priority " + best + " match artifactId=" + artifactId
                            + ": " + top.stream().map(TrustPolicy::policyId).toList());
        }
        return PolicyDecision.ok(top.get(0), "selected policy " + top.get(0).policyId()
                + " at priority " + best + " (config " + snapshot.versionToken() + ")");
    }

    /** 策略引用的密钥在当前快照中必须存在且未撤销/未过期。 */
    private RejectReason checkKeyReferences(TrustPolicy policy, ConfigurationSnapshot snapshot) {
        RejectReason signerRefs = checkRefs(policy.allowedSignerKeyIds(), snapshot);
        if (signerRefs != null) {
            return signerRefs;
        }
        return checkRefs(policy.allowedSbomSignerKeyIds(), snapshot);
    }

    /**
     * 请求期引用检查只查存在性（缺失 → UNTRUSTED_KEY）；密钥撤销/过期的细分结论
     * （KEY_REVOKED/KEY_EXPIRED）由后续签名/证明阶段给出。发布期的严格信任校验
     * （不得引用撤销/过期密钥）已在 GovernanceManager 发布策略时完成。
     */
    private RejectReason checkRefs(List<String> keyIds, ConfigurationSnapshot snapshot) {
        if (keyIds == null) {
            return null;
        }
        for (String keyId : keyIds) {
            if (!snapshot.keys().containsKey(keyId)) {
                return RejectReason.UNTRUSTED_KEY;
            }
        }
        return null;
    }

    static String idempotencyKey(String requestHash, long configVersion) {
        return requestHash + "#v" + configVersion;
    }

    /** 请求规范化哈希：幂等键，覆盖全部输入字段（含 SBOM）。 */
    static String hashRequest(AdmissionRequest request) {
        String provenancePart = request.provenance() == null ? "-" : request.provenance().canonicalPayload()
                + "|" + request.provenance().signerKeyId() + "|" + request.provenance().signature();
        String sbomPart = request.sbom() == null ? "-" : request.sbom().canonicalPayload()
                + "|" + request.sbom().signerKeyId() + "|" + request.sbom().signature();
        return CryptoSupport.sha256Hex(String.join("|",
                request.artifactId(), request.declaredDigest(), request.contentBase64(),
                request.signatureBase64(), request.signerKeyId(), provenancePart, sbomPart));
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
