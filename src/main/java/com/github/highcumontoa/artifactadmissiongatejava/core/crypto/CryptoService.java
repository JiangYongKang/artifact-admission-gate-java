package com.github.highcumontoa.artifactadmissiongatejava.core.crypto;

import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;

/** 本地加密能力：摘要、RSA 签名的生成与校验，PEM 读写。仅依赖 JDK。 */
public interface CryptoService {

    String sha256Hex(Path file);

    String sha256Hex(byte[] content);

    SignatureEnvelope signDigest(PrivateKeyHolder holder, String keyId, String digestHex, java.time.Instant signedAt);

    boolean verifyDigestSignature(PublicKey publicKey, String digestHex, String signatureBase64);

    PublicKey loadPublicKeyPem(Path pemFile);

    String toPem(PublicKey publicKey);

    /** 仅测试/引导时使用的私钥句柄，密钥材料绝不进入日志或对外响应。 */
    final class PrivateKeyHolder {
        private final PrivateKey key;
        public PrivateKeyHolder(PrivateKey key) { this.key = key; }
        public PrivateKey key() { return key; }
    }
}
