package com.github.highcumontoa.artifactadmissiongatejava.core.audit;

import com.github.highcumontoa.artifactadmissiongatejava.domain.AuditEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 内存追加式审计日志。
 * 每条记录打印输入摘要（制品摘要/声明 id）与判定依据；严禁打印任何密钥或签名原文。
 */
@Component
public class InMemoryAuditLog implements AuditLog {

    private static final Logger log = LoggerFactory.getLogger("AUDIT");

    private final CopyOnWriteArrayList<AuditEvent> events = new CopyOnWriteArrayList<>();

    @Override
    public void append(AuditEvent event) {
        events.add(event);
        log.info("admission={} statement={} digest={} {}->{} reason={} detail={}",
                event.admissionId(),
                event.statementId(),
                event.artifactDigest(),
                event.fromStatus(),
                event.toStatus(),
                event.rejectReason(),
                event.detail());
    }

    @Override
    public List<AuditEvent> events() {
        return List.copyOf(events);
    }
}
