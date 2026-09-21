package com.github.highcumontoa.artifactadmissiongatejava.core.policy;

import java.util.List;

/** 策略的配置与一致性快照读取；并发下读到的始终是完整版本。 */
public interface PolicyRepository {

    /** 校验并整体发布一个策略；冲突/非法时失败关闭，旧版本保持不变。 */
    void put(TrustPolicy policy);

    TrustPolicy get(String policyId);

    List<String> policyIds();
}
