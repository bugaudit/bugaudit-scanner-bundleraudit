package me.shib.bugaudit.probe.ruby.bundleraudit;

import me.shib.bugaudit.probe.ProbeConfig;

import java.util.HashMap;
import java.util.Map;

final class BundlerAuditConfig extends ProbeConfig {
    @Override
    protected Map<String, Integer> getDefaultClassificationPriorityMap() {
        return new HashMap<>();
    }
}
