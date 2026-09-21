package com.github.highcumontoa.artifactadmissiongatejava.core.admission;

import com.github.highcumontoa.artifactadmissiongatejava.api.AdmissionRequest;
import com.github.highcumontoa.artifactadmissiongatejava.api.AdmissionResponse;
import com.github.highcumontoa.artifactadmissiongatejava.core.TimeSource;
import com.github.highcumontoa.artifactadmissiongatejava.core.attestation.Attestation;
import com.github.highcumontoa.artifactadmissiongatejava.core.attestation.AttestationCodec;
import com.github.highcumontoa.artifactadmissiongatejava.core.attestation.AttestationVerifier;
import com.github.highcumontoa.artifactadmissiongatejava.core.audit.AuditLog;
import com.github.highcumontoa.artifactadmissiongatejava.core.crypto.CryptoService;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyDecision;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyEvaluator;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyInput;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.TrustPolicy;
import com.github.highcumontoa.artifactadmissiongatejava.domain.AdmissionRecord;
import com.github.highcumontoa.artifactadmissiongatejava.domain.AdmissionStatus;
import com.github.highcumontoa.artifactadmissiongatejava.domain.AuditEvent;
import com.github.highcumontoa.artifactadmissiongatejava.domain.RejectReason;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;

/**
 * 准入编排：联合校验摘要/制品签名/来源证明 -> 信任根 -> 策略，全部失败关闭。
 *
 * 状态语义：
 * - 提交同步完成，外部只能看到 ADMITTED / REJECTED 终态；PENDING 只存在于持锁事务窗口。
 * - 重放（相同 statementId）不会创建新记录：重放计数 +1，并按当前信任根/策略重新复核；
 *   已拒绝的结论不可被重放绕过；已放行的记录若密钥被撤销/过期会被翻转为拒绝。
 */
@Service
public class AdmissionService {

    private static final Logger log = LoggerFactory.getLogger(AdmissionService.class);

    private final AdmissionRepository repository;
    private final PolicyRepository policyRepository;
    private final ArtifactVerifier artifactVerifier;
    private final AttestationVerifier attestationVerifier;
    private final AttestationCodec attestationCodec;
    private final PolicyEvaluator policyEvaluator;
    private final CryptoService cryptoService;
    private final AuditLog auditLog;
    private final TimeSource timeSource;

    public AdmissionService(AdmissionRepository repository,
                            PolicyRepository policyRepository,
                            ArtifactVerifier artifactVerifier,
                            AttestationVerifier attestationVerifier,
                            AttestationCodec attestationCodec,
                            PolicyEvaluator policyEvaluator,
                            CryptoService cryptoService,
                            AuditLog auditLog,
                            TimeSource timeSource) {
        this.repository = repository;
        this.policyRepository = policyRepository;
        this.artifactVerifier = artifactVerifier;
        this.attestationVerifier = attestationVerifier;
        this.attestationCodec = attestationCodec;
        this.policyEvaluator = policyEvaluator;
        this.cryptoService = cryptoService;
        this.auditLog = auditLog;
        this.timeSource = timeSource;
    }

    public AdmissionResponse submit(AdmissionRequest request) {
        validateShape(request);
        Path artifact = Path.of(request.artifactPath());
        Path signature = Path.of(request.signaturePath());
        Path attestationFile = request.attestationPath() == null ? null : Path.of(request.attestationPath());
        Path sbom = request.sbomPath() == null ? null : Path.of(request.sbomPath());

        // 先用证明内容确定 statementId，再在其维度加锁；证明不可读时以独立键串行，仍保持原子判定。
        Preview preview = preview(attestationFile);
        String lockKey = preview.statementId() != null ? preview.statementId()
                : ("no-stmt:" + request.artifactPath() + ":" + request.attestationPath());

        return repository.withStatementLock(lockKey, existing -> {
            Instant now = timeSource.now();
            if (existing.isPresent()) {
                return handleReplay(existing.get(), request, artifact, signature, attestationFile, sbom, now);
            }
            return handleNew(request, artifact, signature, attestationFile, sbom, preview, now, null);
        });
    }

    /**
     * 供批量编排调用：createdSink 非空时，本线程内新建的准入记录 id 会被收集，
     * 以便批次超限时精确回滚；重放命中的既有记录不会进入该集合。
     */
    public AdmissionResponse submit(AdmissionRequest request, java.util.function.Consumer<String> createdSink) {
        validateShape(request);
        Path artifact = Path.of(request.artifactPath());
        Path signature = Path.of(request.signaturePath());
        Path attestationFile = request.attestationPath() == null ? null : Path.of(request.attestationPath());
        Path sbom = request.sbomPath() == null ? null : Path.of(request.sbomPath());
        Preview preview = preview(attestationFile);
        String lockKey = preview.statementId() != null ? preview.statementId()
                : ("no-stmt:" + request.artifactPath() + ":" + request.attestationPath());
        return repository.withStatementLock(lockKey, existing -> {
            Instant now = timeSource.now();
            if (existing.isPresent()) {
                return handleReplay(existing.get(), request, artifact, signature, attestationFile, sbom, now);
            }
            return handleNew(request, artifact, signature, attestationFile, sbom, preview, now, createdSink);
        });
    }

    public AdmissionResponse query(String admissionId) {
        AdmissionRecord record = repository.findById(admissionId)
                .orElseThrow(() -> new NoSuchElementException("admission-not-found:" + admissionId));
        return toResponse(record, false);
    }

    // ---------------- internals ----------------

    private AdmissionResponse handleNew(AdmissionRequest request, Path artifact, Path signature,
                                        Path attestationFile, Path sbom, Preview preview, Instant now,
                                        java.util.function.Consumer<String> createdSink) {
        // 先做制品可读性与摘要检查，使任何时刻持久化的记录都已绑定输入摘要，杜绝含义不明的记录
        if (!java.nio.file.Files.isReadable(artifact)) {
            throw new AdmissionException(RejectReason.BAD_REQUEST, "artifact-unreadable:" + request.artifactPath());
        }
        String digest = cryptoService.sha256Hex(artifact);
        String admissionId = InMemoryAdmissionRepository.newAdmissionId();
        AdmissionRecord record = repository.createPending(
                admissionId, digest, null, preview.statementId(), request.policyId(), now);
        if (createdSink != null) {
            createdSink.accept(admissionId);
        }

        Verdict verdict = evaluate(request, artifact, signature, attestationFile, sbom, preview, now, new ArrayList<>());
        if (verdict.signerKeyId() != null) {
            record.bindSigner(verdict.signerKeyId());
        }
        repository.decide(admissionId, verdict.status(), verdict.reason(), now);
        for (String b : verdict.basis()) {
            record.addTrail(now + " " + b);
        }
        auditLog.append(new AuditEvent(now, admissionId, preview.statementId(), verdict.artifactDigest(),
                AdmissionStatus.PENDING, verdict.status(), verdict.reason(), String.join("; ", verdict.basis())));
        log.info("submit admission={} digest={} decision={}/{} basis={}",
                admissionId, verdict.artifactDigest(), verdict.status(), verdict.reason(), verdict.basis());
        return toResponse(repository.findById(admissionId).orElseThrow(), false);
    }

    private AdmissionResponse handleReplay(AdmissionRecord record, AdmissionRequest request, Path artifact,
                                           Path signature, Path attestationFile, Path sbom, Instant now) {
        // 同一证明重复提交：不产生新记录；按当前信任根/策略复核，防止绕过撤销或拒绝。
        int count = repository.incrementReplay(record.getAdmissionId(), now);
        Verdict verdict = evaluate(request, artifact, signature, attestationFile, sbom,
                preview(attestationFile), now, new ArrayList<>());

        AdmissionStatus previous = record.getStatus();
        RejectReason previousReason = record.getRejectReason();
        AdmissionStatus effective = verdict.status();
        RejectReason effectiveReason = verdict.reason();

        synchronized (record) {
            // 已拒绝的结论永久有效，重放不得推翻
            if (previous == AdmissionStatus.REJECTED) {
                effective = AdmissionStatus.REJECTED;
                effectiveReason = previousReason;
                record.addTrail(now + " replay#" + count + " prior-REJECT upheld: " + previousReason);
            } else {
                record.reevaluate(effective, effectiveReason, now, String.join("; ", verdict.basis()));
            }
        }
        auditLog.append(new AuditEvent(now, record.getAdmissionId(), record.getStatementId(),
                verdict.artifactDigest(), previous, effective, effectiveReason,
                "replay#" + count + " re-evaluated under current trust/policy"));
        log.info("replay admission={} digest={} count={} decision={}/{}",
                record.getAdmissionId(), verdict.artifactDigest(), count, effective, effectiveReason);
        return toResponse(record, true);
    }

    /** 完整校验链；任何一步失败立即返回可区分原因（失败关闭）。 */
    private Verdict evaluate(AdmissionRequest request, Path artifact, Path signature, Path attestationFile,
                             Path sbom, Preview preview, Instant now, List<String> basis) {
        // 1. 制品摘要 + 制品签名 + 密钥状态
        ArtifactVerifier.Result artifactResult =
                artifactVerifier.verify(artifact, request.claimedDigest(), signature, now);
        basis.addAll(artifactResult.basis());
        if (!artifactResult.ok()) {
            return Verdict.of(artifactResult.reason(), artifactResult.actualDigest(), null, basis);
        }
        String digest = artifactResult.actualDigest();
        String signerKeyId = artifactResult.envelope() == null ? null : artifactResult.envelope().keyId();

        // 2. 来源证明：必须存在且可解析
        if (attestationFile == null || !Files.isReadable(attestationFile)) {
            return Verdict.of(RejectReason.ATTESTATION_MISSING, digest, signerKeyId, basis);
        }
        if (preview.malformed()) {
            basis.add("attestation-unparseable");
            return Verdict.of(RejectReason.ATTESTATION_MALFORMED, digest, signerKeyId, basis);
        }
        Attestation attestation = preview.attestation() != null ? preview.attestation() : readAttestation(attestationFile);
        if (attestation == null) {
            return Verdict.of(RejectReason.ATTESTATION_MALFORMED, digest, signerKeyId, basis);
        }
        AttestationVerifier.Result attResult = attestationVerifier.verify(attestation, digest, now);
        basis.addAll(attResult.basis());
        if (!attResult.ok()) {
            return Verdict.of(attResult.reason(), digest, signerKeyId, basis);
        }

        // 3. SBOM（可选）：一旦随提交提供，就必须与证明中声明的 sbomDigest 绑定且内容一致
        if (sbom != null) {
            if (!Files.isReadable(sbom)) {
                return Verdict.of(RejectReason.SBOM_DIGEST_MISMATCH, digest, signerKeyId, basis);
            }
            String sbomDigest = cryptoService.sha256Hex(sbom);
            basis.add("sbomDigest=" + sbomDigest);
            String declared = attestation.sbomDigest();
            if (declared == null || !declared.equals(sbomDigest)) {
                basis.add("sbom-binding declared=" + declared + " actual=" + sbomDigest);
                return Verdict.of(RejectReason.SBOM_DIGEST_MISMATCH, digest, signerKeyId, basis);
            }
        }

        // 4. 策略：策略缺失/冲突/不匹配均失败关闭
        TrustPolicy policy = policyRepository.get(request.policyId());
        if (policy == null) {
            basis.add("policy-missing:" + request.policyId());
            return Verdict.of(RejectReason.POLICY_MISSING, digest, signerKeyId, basis);
        }
        PolicyInput input = new PolicyInput(
                signerKeyId,
                attestation.claims().buildSource(),
                attestation.claims().artifactId());
        PolicyDecision decision = policyEvaluator.evaluate(policy, input);
        basis.addAll(decision.basis());
        if (!decision.allowed()) {
            return Verdict.of(decision.reason(), digest, signerKeyId, basis);
        }
        return Verdict.admitted(digest, signerKeyId, basis);
    }

    private Preview preview(Path attestationFile) {
        if (attestationFile == null || !Files.isReadable(attestationFile)) {
            return new Preview(null, null, false);
        }
        try {
            Attestation attestation = attestationCodec.read(attestationFile);
            return new Preview(attestation.statementId(), attestation, false);
        } catch (RuntimeException e) {
            // 文件存在但无法解析：属于证明畸形，而非证明缺失
            return new Preview(null, null, true);
        }
    }

    private Attestation readAttestation(Path file) {
        try {
            return attestationCodec.read(file);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private void validateShape(AdmissionRequest request) {
        if (request == null) {
            throw new AdmissionException(RejectReason.BAD_REQUEST, "request-null");
        }
        if (request.artifactPath() == null || request.artifactPath().isBlank()
                || request.signaturePath() == null || request.signaturePath().isBlank()
                || request.policyId() == null || request.policyId().isBlank()) {
            throw new AdmissionException(RejectReason.BAD_REQUEST,
                    "artifactPath, signaturePath, policyId are required");
        }
    }

    private AdmissionResponse toResponse(AdmissionRecord r, boolean replay) {
        return new AdmissionResponse(
                r.getAdmissionId(),
                r.getStatus(),
                r.getRejectReason(),
                r.getArtifactDigest(),
                r.getSignerKeyId(),
                r.getStatementId(),
                r.getPolicyId(),
                replay,
                r.getReplayCount(),
                r.getCreatedAt(),
                r.getDecidedAt(),
                r.getAuditTrail());
    }

    private record Preview(String statementId, Attestation attestation, boolean malformed) {
    }

    private record Verdict(AdmissionStatus status, RejectReason reason, String artifactDigest,
                           String signerKeyId, List<String> basis) {
        static Verdict of(RejectReason reason, String digest, String signerKeyId, List<String> basis) {
            basis.add("verdict=REJECT/" + reason);
            return new Verdict(AdmissionStatus.REJECTED, reason, digest, signerKeyId, List.copyOf(basis));
        }

        static Verdict admitted(String digest, String signerKeyId, List<String> basis) {
            basis.add("verdict=ADMITTED");
            return new Verdict(AdmissionStatus.ADMITTED, null, digest, signerKeyId, List.copyOf(basis));
        }
    }
}
