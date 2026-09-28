package com.github.highcumontoa.artifactadmissiongatejava.config;

/**
 * 运行期配置治理异常：发布阶段拒绝非法配置（矛盾策略、引用不受信任密钥等），
 * 不允许其进入生效配置。
 *
 * @param kind 拒绝类别
 */
public class GovernanceException extends RuntimeException {

    public enum Kind {
        /** 密钥已存在 / 不存在等状态冲突。 */
        KEY_CONFLICT,
        /** 策略 ID 重复或目标策略不存在。 */
        POLICY_CONFLICT,
        /** 策略自相矛盾或非法（正则不可编译、同优先级重叠）。 */
        POLICY_INVALID,
        /** 策略引用了当前不受信任的密钥。 */
        POLICY_KEY_UNTRUSTED
    }

    private final Kind kind;

    public GovernanceException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }
}
