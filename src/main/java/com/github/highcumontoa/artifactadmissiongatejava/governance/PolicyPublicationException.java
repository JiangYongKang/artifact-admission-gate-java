package com.github.highcumontoa.artifactadmissiongatejava.governance;

/**
 * 策略/信任配置在发布阶段被拒绝：自相矛盾或引用当前不受信任的密钥。
 * 发布失败时治理状态保持不变（原子语义）。
 */
public class PolicyPublicationException extends RuntimeException {

    private final String code;

    public PolicyPublicationException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
