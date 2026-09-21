package com.github.highcumontoa.artifactadmissiongatejava.core.audit;

import com.github.highcumontoa.artifactadmissiongatejava.domain.AuditEvent;

import java.util.List;

/** 审计日志：只追加、线程安全；禁止写入密钥材料。 */
public interface AuditLog {
    void append(AuditEvent event);
    List<AuditEvent> events();
}
