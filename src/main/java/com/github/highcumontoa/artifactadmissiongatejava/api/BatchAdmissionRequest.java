package com.github.highcumontoa.artifactadmissiongatejava.api;

import java.util.List;

/** 批量准入请求。 */
public record BatchAdmissionRequest(List<AdmissionRequest> items) {
}
