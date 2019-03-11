package me.shib.bugaudit.scanner.ruby.bundleraudit;


import me.shib.bugaudit.scanner.BugAuditScannerConfig;

import java.util.HashMap;
import java.util.Map;

final class BundlerAuditConfig extends BugAuditScannerConfig {
    @Override
    protected Map<String, Integer> getDefaultClassificationPriorityMap() {
        return new HashMap<>();
    }
}
