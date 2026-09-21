package com.github.highcumontoa.artifactadmissiongatejava.trust;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.HexFormat;

/** 仅依赖 JDK 的摘要与 Ed25519 验签工具，保证本地可复现。 */
public final class CryptoSupport {

    private CryptoSupport() {
    }

    public static String sha256Hex(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static String sha256Hex(String text) {
        return sha256Hex(text.getBytes(StandardCharsets.UTF_8));
    }

    /** 验签；任何异常一律视为签名无效，不向外泄露内部细节。 */
    public static boolean verifyEd25519(PublicKey publicKey, byte[] payload, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKey);
            verifier.update(payload);
            return verifier.verify(signature);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }
}
