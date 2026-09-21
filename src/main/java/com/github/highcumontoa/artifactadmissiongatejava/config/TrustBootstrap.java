package com.github.highcumontoa.artifactadmissiongatejava.config;

import com.github.highcumontoa.artifactadmissiongatejava.core.admission.AdmissionException;
import com.github.highcumontoa.artifactadmissiongatejava.core.crypto.CryptoService;
import com.github.highcumontoa.artifactadmissiongatejava.core.crypto.JacksonSupport;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.PolicyRepository;
import com.github.highcumontoa.artifactadmissiongatejava.core.policy.TrustPolicy;
import com.github.highcumontoa.artifactadmissiongatejava.core.trust.TrustedKey;
import com.github.highcumontoa.artifactadmissiongatejava.core.trust.TrustStore;
import com.github.highcumontoa.artifactadmissiongatejava.domain.KeyState;
import com.github.highcumontoa.artifactadmissiongatejava.domain.RejectReason;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

/**
 * 启动时从本地目录装载：
 * - trustDir：每个子目录代表一个 keyId，含 public.pem 与 meta.json（state/expiresAt/rotatedAt/replacedKeyId）；
 * - policiesDir：每个 *.json 是一个 TrustPolicy。
 * 目录为空/未配置时系统以空信任根启动——任何引用密钥的校验都会 KEY_UNTRUSTED，失败关闭。
 */
public class TrustBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(TrustBootstrap.class);

    private final GateProperties properties;
    private final TrustStore trustStore;
    private final PolicyRepository policyRepository;
    private final CryptoService cryptoService;

    public TrustBootstrap(GateProperties properties, TrustStore trustStore,
                          PolicyRepository policyRepository, CryptoService cryptoService) {
        this.properties = properties;
        this.trustStore = trustStore;
        this.policyRepository = policyRepository;
        this.cryptoService = cryptoService;
    }

    @Override
    public void run(ApplicationArguments args) {
        loadTrustRoots();
        loadPolicies();
    }

    private void loadTrustRoots() {
        String dir = properties.getTrustDir();
        if (dir == null || dir.isBlank() || !Files.isDirectory(Path.of(dir))) {
            log.warn("trust-dir not configured or missing; starting with EMPTY trust store (fail-closed)");
            return;
        }
        try (Stream<Path> children = Files.list(Path.of(dir))) {
            children.filter(Files::isDirectory).forEach(this::loadKeyDir);
        } catch (AdmissionException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("cannot-read-trust-dir:" + dir, e);
        }
        log.info("trust roots loaded: {}", trustStore.keyIds());
    }

    @SuppressWarnings("unchecked")
    private void loadKeyDir(Path keyDir) {
        try {
            String keyId = keyDir.getFileName().toString();
            PublicKey publicKey = cryptoService.loadPublicKeyPem(keyDir.resolve("public.pem"));
            KeyState state = KeyState.ACTIVE;
            String expiresAt = null;
            String rotatedAt = null;
            String replacedKeyId = null;
            Path meta = keyDir.resolve("meta.json");
            if (Files.isReadable(meta)) {
                Map<String, Object> m = JacksonSupport.mapper().readValue(Files.readAllBytes(meta), HashMap.class);
                if (m.get("state") != null) {
                    state = KeyState.valueOf(String.valueOf(m.get("state")));
                }
                expiresAt = (String) m.get("expiresAt");
                rotatedAt = (String) m.get("rotatedAt");
                replacedKeyId = (String) m.get("replacedKeyId");
            }
            trustStore.register(new TrustedKey(keyId, publicKey, state,
                    expiresAt == null ? null : java.time.Instant.parse(expiresAt),
                    rotatedAt == null ? null : java.time.Instant.parse(rotatedAt),
                    replacedKeyId));
        } catch (Exception e) {
            // 引导期任何密钥装载失败都失败关闭，避免“半套信任根”启动
            throw new AdmissionException(RejectReason.KEY_UNTRUSTED,
                    "trust-bootstrap-failed:" + keyDir.getFileName());
        }
    }

    private void loadPolicies() {
        String dir = properties.getPoliciesDir();
        if (dir == null || dir.isBlank() || !Files.isDirectory(Path.of(dir))) {
            log.warn("policies-dir not configured or missing; no policies loaded (fail-closed)");
            return;
        }
        try (Stream<Path> files = Files.list(Path.of(dir))) {
            files.filter(p -> p.getFileName().toString().endsWith(".json")).forEach(this::loadPolicyFile);
        } catch (AdmissionException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("cannot-read-policies-dir:" + dir, e);
        }
        log.info("policies loaded: {}", policyRepository.policyIds());
    }

    private void loadPolicyFile(Path file) {
        final TrustPolicy policy;
        try {
            policy = JacksonSupport.mapper().readValue(Files.readAllBytes(file), TrustPolicy.class);
        } catch (Exception e) {
            throw new AdmissionException(RejectReason.POLICY_CONFLICT,
                    "policy-bootstrap-unreadable:" + file.getFileName());
        }
        // 冲突/非法由仓库抛出 AdmissionException 原样向上传播，不被包装成其他类型
        policyRepository.put(policy);
    }
}
