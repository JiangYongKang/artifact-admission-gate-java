package com.github.highcumontoa.artifactadmissiongatejava.web;

import com.github.highcumontoa.artifactadmissiongatejava.api.ConfigurePolicyRequest;
import com.github.highcumontoa.artifactadmissiongatejava.api.RegisterKeyRequest;
import com.github.highcumontoa.artifactadmissiongatejava.core.TimeSource;
import com.github.highcumontoa.artifactadmissiongatejava.core.crypto.CryptoService;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyRepository;
import com.github.highcumontoa.artifactadmissiongatejava.core.trust.TrustedKey;
import com.github.highcumontoa.artifactadmissiongatejava.core.trust.TrustStore;
import org.springframework.web.bind.annotation.*;

import java.nio.file.Path;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 信任根与策略的本地管理入口。
 * 公钥仅从本地 PEM 路径读取，列表与响应中只暴露 keyId/状态/时间点，绝不回显任何密钥材料。
 */
@RestController
@RequestMapping("/api/admin")
public class TrustAdminController {

    private final TrustStore trustStore;
    private final PolicyRepository policyRepository;
    private final CryptoService cryptoService;
    private final TimeSource timeSource;

    public TrustAdminController(TrustStore trustStore, PolicyRepository policyRepository,
                                CryptoService cryptoService, TimeSource timeSource) {
        this.trustStore = trustStore;
        this.policyRepository = policyRepository;
        this.cryptoService = cryptoService;
        this.timeSource = timeSource;
    }

    @PostMapping("/keys")
    public Map<String, Object> registerKey(@RequestBody RegisterKeyRequest request) {
        if (request.publicKeyPemPath() == null || request.publicKeyPemPath().isBlank()) {
            throw new IllegalArgumentException("publicKeyPemPath-required");
        }
        PublicKey publicKey = cryptoService.loadPublicKeyPem(Path.of(request.publicKeyPemPath()));
        trustStore.register(new TrustedKey(request.keyId(), publicKey, request.state(),
                request.expiresAt(), request.rotatedAt(), request.replacedKeyId()));
        return keyView(request.keyId(), "registered");
    }

    @PostMapping("/keys/{keyId}/revoke")
    public Map<String, Object> revoke(@PathVariable String keyId) {
        trustStore.revoke(keyId, timeSource.now());
        return keyView(keyId, "revoked");
    }

    @PostMapping("/keys/{oldKeyId}/rotate")
    public Map<String, Object> rotate(@PathVariable String oldKeyId, @RequestBody RegisterKeyRequest newKey) {
        if (newKey.publicKeyPemPath() == null || newKey.publicKeyPemPath().isBlank()) {
            throw new IllegalArgumentException("publicKeyPemPath-required");
        }
        // 新根先注册，再在同一同步流程中完成旧根 ROTATED 标记；任一步失败则不改变既有状态
        if (trustStore.get(newKey.keyId()) == null) {
            PublicKey publicKey = cryptoService.loadPublicKeyPem(Path.of(newKey.publicKeyPemPath()));
            trustStore.register(new TrustedKey(newKey.keyId(), publicKey,
                    com.github.highcumontoa.artifactadmissiongatejava.domain.KeyState.ACTIVE,
                    newKey.expiresAt(), null, oldKeyId));
        }
        trustStore.rotate(oldKeyId, newKey.keyId(),
                newKey.rotatedAt() != null ? newKey.rotatedAt() : timeSource.now());
        return keyView(newKey.keyId(), "rotated-from-" + oldKeyId);
    }

    @GetMapping("/keys")
    public List<Map<String, Object>> listKeys() {
        List<Map<String, Object>> view = new ArrayList<>();
        for (String id : trustStore.keyIds()) {
            TrustedKey key = trustStore.get(id);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("keyId", key.getKeyId());
            m.put("state", key.getState());
            m.put("expiresAt", key.getExpiresAt());
            m.put("rotatedAt", key.getRotatedAt());
            m.put("replacedKeyId", key.getReplacedKeyId());
            view.add(m);
        }
        return view;
    }

    @PostMapping("/policies")
    public Map<String, Object> configurePolicy(@RequestBody ConfigurePolicyRequest request) {
        policyRepository.put(request.policy());
        return Map.of("policyId", request.policy().policyId(), "status", "configured",
                "ruleCount", request.policy().rules().size());
    }

    @GetMapping("/policies")
    public List<String> listPolicies() {
        return policyRepository.policyIds();
    }

    private Map<String, Object> keyView(String keyId, String action) {
        TrustedKey key = trustStore.get(keyId);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("keyId", keyId);
        m.put("state", key == null ? null : key.getState());
        m.put("action", action);
        return m;
    }
}
