package com.github.highcumontoa.artifactadmissiongatejava.core.crypto;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;

/**
 * 基于 JDK 的本地加密实现：SHA-256 摘要、SHA256withRSA 签名、X.509 PEM 读写。
 * 不依赖任何外部服务或真实凭据。
 */
@Service
public class JdkCryptoService implements CryptoService {

    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    @Override
    public String sha256Hex(Path file) {
        try {
            byte[] data = Files.readAllBytes(file);
            return sha256Hex(data);
        } catch (Exception e) {
            // 不打印文件内容，避免材料泄漏；路径不属于敏感信息
            throw new IllegalStateException("digest-failed:" + file, e);
        }
    }

    @Override
    public String sha256Hex(byte[] content) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(content);
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("digest-algorithm-unavailable", e);
        }
    }

    @Override
    public SignatureEnvelope signDigest(PrivateKeyHolder holder, String keyId, String digestHex, Instant signedAt) {
        try {
            Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
            sig.initSign(holder.key());
            sig.update(digestHex.getBytes(StandardCharsets.UTF_8));
            String b64 = Base64.getEncoder().encodeToString(sig.sign());
            return new SignatureEnvelope(keyId, digestHex, SIGNATURE_ALGORITHM, signedAt, b64);
        } catch (Exception e) {
            throw new IllegalStateException("sign-failed:" + keyId, e);
        }
    }

    @Override
    public boolean verifyDigestSignature(PublicKey publicKey, String digestHex, String signatureBase64) {
        if (publicKey == null || digestHex == null || signatureBase64 == null) {
            return false;
        }
        try {
            Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
            sig.initVerify(publicKey);
            sig.update(digestHex.getBytes(StandardCharsets.UTF_8));
            return sig.verify(Base64.getDecoder().decode(signatureBase64));
        } catch (Exception e) {
            // 任何解码/验签异常都视为签名无效（失败关闭），不向上泄漏细节
            return false;
        }
    }

    @Override
    public PublicKey loadPublicKeyPem(Path pemFile) {
        try {
            String pem = Files.readString(pemFile, StandardCharsets.UTF_8);
            return parsePemPublicKey(pem);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("cannot-load-public-key:" + pemFile, e);
        }
    }

    @Override
    public String toPem(PublicKey publicKey) {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(publicKey.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----\n";
    }

    /** 解析 X.509 SubjectPublicKeyInfo PEM；仅返回公钥对象，不记录材料。 */
    public static PublicKey parsePemPublicKey(String pem) {
        try {
            String body = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(body);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid-public-key-pem", e);
        }
    }

}
