package com.github.highcumontoa.artifactadmissiongatejava.api;

import com.github.highcumontoa.artifactadmissiongatejava.api.dto.PolicyRequest;
import com.github.highcumontoa.artifactadmissiongatejava.api.dto.RegisterKeyRequest;
import com.github.highcumontoa.artifactadmissiongatejava.api.dto.RotateKeyRequest;
import com.github.highcumontoa.artifactadmissiongatejava.governance.GovernanceRegistry;
import com.github.highcumontoa.artifactadmissiongatejava.governance.GovernanceSnapshot;
import com.github.highcumontoa.artifactadmissiongatejava.policy.TrustPolicy;
import com.github.highcumontoa.artifactadmissiongatejava.trust.KeyState;
import com.github.highcumontoa.artifactadmissiongatejava.trust.TrustedKey;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 运行期治理接口：密钥的新增/轮换/撤销/过期，策略的发布（新增或同 ID 替换）/下线。
 * 所有改动原子发布、立即生效；自相矛盾或引用未受信密钥的策略在发布期返回 422。
 * 响应只含 keyId、状态与配置版本，绝不回传私钥材料。
 */
@RestController
@RequestMapping("/api/governance")
public class GovernanceController {

    private final GovernanceRegistry registry;

    public GovernanceController(GovernanceRegistry registry) {
        this.registry = registry;
    }

    @GetMapping("/snapshot")
    public Map<String, Object> snapshot() {
        GovernanceSnapshot snap = registry.current();
        List<Map<String, String>> keys = snap.keys().values().stream()
                .map(k -> Map.of("keyId", k.keyId(), "state", k.state().name()))
                .toList();
        List<Map<String, Object>> policies = snap.policies().stream()
                .map(p -> {
                    Map<String, Object> view = new LinkedHashMap<>();
                    view.put("policyId", p.policyId());
                    view.put("priority", p.priority());
                    view.put("artifactIdPattern", p.artifactIdPattern());
                    view.put("allowedSignerKeyIds", p.allowedSignerKeyIds());
                    view.put("allowedBuilderIds", p.allowedBuilderIds());
                    view.put("requireProvenance", p.requireProvenance());
                    view.put("requireManifest", p.requireManifest());
                    view.put("allowedComponentPatterns", p.allowedComponentPatterns());
                    return view;
                }).toList();
        return Map.of("configVersion", snap.version(), "keys", keys, "policies", policies);
    }

    @PostMapping("/keys")
    public ResponseEntity<Map<String, Object>> registerKey(@RequestBody RegisterKeyRequest request) {
        PublicKey publicKey = decodeEd25519PublicKey(request.publicKeyBase64());
        registry.registerKey(new TrustedKey(request.keyId(), publicKey, KeyState.ACTIVE,
                request.notBefore(), request.notAfter(), null));
        return ResponseEntity.ok(Map.of("status", "REGISTERED",
                "keyId", request.keyId(), "configVersion", registry.current().version()));
    }

    @PostMapping("/keys/rotate")
    public ResponseEntity<Map<String, Object>> rotateKey(@RequestBody RotateKeyRequest request) {
        PublicKey publicKey = decodeEd25519PublicKey(request.newPublicKeyBase64());
        registry.rotateKey(request.oldKeyId(),
                new TrustedKey(request.newKeyId(), publicKey, KeyState.ACTIVE, null, null, null),
                request.retiredAt());
        return ResponseEntity.ok(Map.of("status", "ROTATED",
                "oldKeyId", request.oldKeyId(), "newKeyId", request.newKeyId(),
                "configVersion", registry.current().version()));
    }

    @PostMapping("/keys/{keyId}/revoke")
    public ResponseEntity<Map<String, Object>> revokeKey(@PathVariable String keyId) {
        registry.revokeKey(keyId);
        return ResponseEntity.ok(Map.of("status", "REVOKED", "keyId", keyId,
                "configVersion", registry.current().version()));
    }

    @PostMapping("/keys/{keyId}/expire")
    public ResponseEntity<Map<String, Object>> expireKey(@PathVariable String keyId) {
        registry.expireKey(keyId);
        return ResponseEntity.ok(Map.of("status", "EXPIRED", "keyId", keyId,
                "configVersion", registry.current().version()));
    }

    @PostMapping("/policies")
    public ResponseEntity<Map<String, Object>> publishPolicy(@RequestBody PolicyRequest request) {
        if (request.policyId() == null || request.priority() == null) {
            throw new IllegalArgumentException("policyId and priority are required");
        }
        TrustPolicy policy = new TrustPolicy(
                request.policyId(),
                request.priority(),
                request.artifactIdPattern(),
                request.allowedSignerKeyIds(),
                request.allowedBuilderIds(),
                Boolean.TRUE.equals(request.requireProvenance()),
                Boolean.TRUE.equals(request.requireManifest()),
                request.allowedComponentPatterns());
        registry.publishPolicy(policy);
        return ResponseEntity.ok(Map.of("status", "PUBLISHED",
                "policyId", request.policyId(), "configVersion", registry.current().version()));
    }

    @PostMapping("/policies/{policyId}/retire")
    public ResponseEntity<Map<String, Object>> retirePolicy(@PathVariable String policyId) {
        registry.retirePolicy(policyId);
        return ResponseEntity.ok(Map.of("status", "RETIRED", "policyId", policyId,
                "configVersion", registry.current().version()));
    }

    static PublicKey decodeEd25519PublicKey(String base64) {
        if (base64 == null || base64.isBlank()) {
            throw new IllegalArgumentException("publicKeyBase64 is required");
        }
        try {
            byte[] der = Base64.getDecoder().decode(base64);
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid X.509 Ed25519 public key: " + e.getMessage());
        }
    }
}
