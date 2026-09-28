package com.github.highcumontoa.artifactadmissiongatejava.api;

import com.github.highcumontoa.artifactadmissiongatejava.api.dto.KeyEnrollmentRequest;
import com.github.highcumontoa.artifactadmissiongatejava.api.dto.KeyRotationRequest;
import com.github.highcumontoa.artifactadmissiongatejava.api.dto.PolicyUpsertRequest;
import com.github.highcumontoa.artifactadmissiongatejava.config.ConfigurationSnapshot;
import com.github.highcumontoa.artifactadmissiongatejava.config.GovernanceException;
import com.github.highcumontoa.artifactadmissiongatejava.config.GovernanceManager;
import com.github.highcumontoa.artifactadmissiongatejava.policy.TrustPolicy;
import com.github.highcumontoa.artifactadmissiongatejava.trust.CryptoSupport;
import com.github.highcumontoa.artifactadmissiongatejava.trust.KeyState;
import com.github.highcumontoa.artifactadmissiongatejava.trust.TrustedKey;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.PublicKey;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 运行期配置治理接口：密钥与策略的新增/轮换/撤销/过期、发布/替换/下线。
 * 非法配置在发布阶段以 4xx 明确拒绝，不进入生效配置；成功变更返回新版本号。
 */
@RestController
@RequestMapping("/api/governance")
public class GovernanceController {

    private final GovernanceManager governance;

    public GovernanceController(GovernanceManager governance) {
        this.governance = governance;
    }

    /** 当前生效配置版本（只回 keyId/状态与策略ID，绝不回密钥材料）。 */
    @GetMapping("/snapshot")
    public Map<String, Object> snapshot() {
        ConfigurationSnapshot s = governance.currentSnapshot();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("configVersion", s.version());
        body.put("versionToken", s.versionToken());
        body.put("keys", s.keys().values().stream().map(k -> {
            Map<String, Object> view = new LinkedHashMap<>();
            view.put("keyId", k.keyId());
            view.put("state", k.state().name());
            return view;
        }).toList());
        body.put("policies", s.policies().stream().map(p -> {
            Map<String, Object> view = new LinkedHashMap<>();
            view.put("policyId", p.policyId());
            view.put("priority", p.priority());
            return view;
        }).toList());
        return body;
    }

    @PostMapping("/keys")
    public ResponseEntity<Map<String, Object>> registerKey(@RequestBody KeyEnrollmentRequest request) {
        PublicKey publicKey = CryptoSupport.publicKeyFromX509Base64(request.publicKeyBase64());
        TrustedKey key = new TrustedKey(request.keyId(), publicKey, KeyState.ACTIVE,
                parseInstant(request.notBefore()), parseInstant(request.notAfter()), null);
        governance.registerKey(key);
        return ResponseEntity.status(HttpStatus.CREATED).body(ok());
    }

    @PostMapping("/keys/rotate")
    public ResponseEntity<Map<String, Object>> rotateKey(@RequestBody KeyRotationRequest request) {
        PublicKey publicKey = CryptoSupport.publicKeyFromX509Base64(request.newPublicKeyBase64());
        Instant retiredAt = request.retiredAt() == null || request.retiredAt().isBlank()
                ? Instant.now() : parseInstant(request.retiredAt());
        TrustedKey newKey = new TrustedKey(request.newKeyId(), publicKey, KeyState.ACTIVE,
                Instant.now(), null, null);
        governance.rotateKey(request.oldKeyId(), newKey, retiredAt);
        return ResponseEntity.ok(ok());
    }

    @PostMapping("/keys/{keyId}/revoke")
    public ResponseEntity<Map<String, Object>> revokeKey(@PathVariable String keyId) {
        governance.revokeKey(keyId);
        return ResponseEntity.ok(ok());
    }

    @PostMapping("/keys/{keyId}/expire")
    public ResponseEntity<Map<String, Object>> expireKey(@PathVariable String keyId) {
        governance.expireKey(keyId);
        return ResponseEntity.ok(ok());
    }

    @PostMapping("/policies")
    public ResponseEntity<Map<String, Object>> publishPolicy(@RequestBody PolicyUpsertRequest request) {
        governance.publishPolicy(toPolicy(request));
        return ResponseEntity.status(HttpStatus.CREATED).body(ok());
    }

    @PutMapping("/policies/{policyId}")
    public ResponseEntity<Map<String, Object>> replacePolicy(@PathVariable String policyId,
                                                             @RequestBody PolicyUpsertRequest request) {
        governance.replacePolicy(toPolicy(withId(request, policyId)));
        return ResponseEntity.ok(ok());
    }

    @DeleteMapping("/policies/{policyId}")
    public ResponseEntity<Map<String, Object>> retirePolicy(@PathVariable String policyId) {
        governance.retirePolicy(policyId);
        return ResponseEntity.ok(ok());
    }

    private Map<String, Object> ok() {
        return Map.of("configVersion", governance.currentSnapshot().version(),
                "versionToken", governance.currentSnapshot().versionToken());
    }

    private static PolicyUpsertRequest withId(PolicyUpsertRequest r, String policyId) {
        return new PolicyUpsertRequest(policyId, r.priority(), r.artifactIdPattern(),
                r.allowedSignerKeyIds(), r.allowedBuilderIds(), r.allowedSbomSignerKeyIds(),
                r.allowedComponents(), r.requireProvenance(), r.requireSbom());
    }

    private static TrustPolicy toPolicy(PolicyUpsertRequest r) {
        return new TrustPolicy(r.policyId(), r.priority() == null ? 100 : r.priority(),
                r.artifactIdPattern(),
                r.allowedSignerKeyIds() == null ? null : List.copyOf(r.allowedSignerKeyIds()),
                r.allowedBuilderIds() == null ? null : List.copyOf(r.allowedBuilderIds()),
                r.requireProvenance(),
                r.allowedSbomSignerKeyIds() == null ? null : List.copyOf(r.allowedSbomSignerKeyIds()),
                r.allowedComponents() == null ? null : List.copyOf(r.allowedComponents()),
                r.requireSbom());
    }

    private static Instant parseInstant(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (Exception e) {
            return OffsetDateTime.parse(value).toInstant();
        }
    }

    /** 密钥/策略状态冲突 → 409；策略非法或引用不受信任密钥 → 400；请求体密钥编码错误 → 400。 */
    @ExceptionHandler(GovernanceException.class)
    public ResponseEntity<Map<String, String>> handleGovernance(GovernanceException e) {
        HttpStatus status = e.kind() == GovernanceException.Kind.KEY_CONFLICT
                || e.kind() == GovernanceException.Kind.POLICY_CONFLICT
                ? HttpStatus.CONFLICT : HttpStatus.BAD_REQUEST;
        return ResponseEntity.status(status).body(Map.of(
                "error", e.kind().name(), "detail", e.getMessage() == null ? "" : e.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleBadInput(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of(
                "error", "BAD_REQUEST", "detail", e.getMessage() == null ? "" : e.getMessage()));
    }
}
