package com.dpi.service;

import com.dpi.model.AppType;
import com.dpi.model.BlockingRule;
import com.dpi.model.BlockingRule.RuleType;
import com.dpi.repository.BlockingRuleRepository;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages DPI blocking rules (IP, App, Domain, Port).
 * Java port of C++ DPI::RuleManager.
 *
 * Thread-safe in-memory sets are kept in sync with the database.
 * Fast-path checks use the in-memory sets for performance.
 */
@Service
public class RuleManagerService {

    private static final Logger log = LoggerFactory.getLogger(RuleManagerService.class);

    private final BlockingRuleRepository ruleRepo;

    // In-memory sets for fast packet-path checks (mirrors C++ RuleManager private fields)
    private final Set<String>  blockedIps      = ConcurrentHashMap.newKeySet();
    private final Set<AppType> blockedApps     = ConcurrentHashMap.newKeySet();
    private final Set<String>  blockedDomains  = ConcurrentHashMap.newKeySet();
    private final Set<Integer> blockedPorts    = ConcurrentHashMap.newKeySet();

    public RuleManagerService(BlockingRuleRepository ruleRepo) {
        this.ruleRepo = ruleRepo;
    }

    /** Load active rules from DB into memory on startup. */
    @PostConstruct
    public void loadFromDatabase() {
        List<BlockingRule> active = ruleRepo.findByActive(true);
        for (BlockingRule rule : active) {
            applyToMemory(rule);
        }
        log.info("[RuleManager] Loaded {} rules from database", active.size());
    }

    // -----------------------------------------------------------------------
    // IP Blocking (mirrors C++ RuleManager::blockIP / unblockIP)
    // -----------------------------------------------------------------------

    @Transactional
    public void blockIp(String ip) {
        blockedIps.add(ip);
        persistRule(RuleType.IP, ip);
        log.info("[RuleManager] Blocked IP: {}", ip);
    }

    @Transactional
    public void unblockIp(String ip) {
        blockedIps.remove(ip);
        deactivateRule(RuleType.IP, ip);
        log.info("[RuleManager] Unblocked IP: {}", ip);
    }

    public boolean isIpBlocked(String ip) {
        return blockedIps.contains(ip);
    }

    public List<String> getBlockedIps() {
        return new ArrayList<>(blockedIps);
    }

    // -----------------------------------------------------------------------
    // Application Blocking (mirrors C++ RuleManager::blockApp / unblockApp)
    // -----------------------------------------------------------------------

    @Transactional
    public void blockApp(AppType app) {
        blockedApps.add(app);
        persistRule(RuleType.APP, app.name());
        log.info("[RuleManager] Blocked app: {}", app);
    }

    @Transactional
    public void blockApp(String appName) {
        try {
            blockApp(AppType.valueOf(appName.toUpperCase()));
        } catch (IllegalArgumentException e) {
            log.warn("[RuleManager] Unknown app type: {}", appName);
        }
    }

    @Transactional
    public void unblockApp(AppType app) {
        blockedApps.remove(app);
        deactivateRule(RuleType.APP, app.name());
        log.info("[RuleManager] Unblocked app: {}", app);
    }

    public boolean isAppBlocked(AppType app) {
        return blockedApps.contains(app);
    }

    public List<AppType> getBlockedApps() {
        return new ArrayList<>(blockedApps);
    }

    // -----------------------------------------------------------------------
    // Domain Blocking (mirrors C++ RuleManager::blockDomain / isDomainBlocked)
    // -----------------------------------------------------------------------

    @Transactional
    public void blockDomain(String domain) {
        blockedDomains.add(domain.toLowerCase());
        persistRule(RuleType.DOMAIN, domain.toLowerCase());
        log.info("[RuleManager] Blocked domain: {}", domain);
    }

    @Transactional
    public void unblockDomain(String domain) {
        blockedDomains.remove(domain.toLowerCase());
        deactivateRule(RuleType.DOMAIN, domain.toLowerCase());
        log.info("[RuleManager] Unblocked domain: {}", domain);
    }

    /**
     * Check if domain is blocked. Supports wildcard prefix (*.example.com).
     * Mirrors C++ RuleManager::isDomainBlocked() with wildcard matching.
     */
    public boolean isDomainBlocked(String domain) {
        if (domain == null) return false;
        String lower = domain.toLowerCase();
        for (String pattern : blockedDomains) {
            if (domainMatchesPattern(lower, pattern)) return true;
        }
        return false;
    }

    public List<String> getBlockedDomains() {
        return new ArrayList<>(blockedDomains);
    }

    // -----------------------------------------------------------------------
    // Port Blocking (mirrors C++ RuleManager::blockPort)
    // -----------------------------------------------------------------------

    @Transactional
    public void blockPort(int port) {
        blockedPorts.add(port);
        persistRule(RuleType.PORT, String.valueOf(port));
        log.info("[RuleManager] Blocked port: {}", port);
    }

    @Transactional
    public void unblockPort(int port) {
        blockedPorts.remove(port);
        deactivateRule(RuleType.PORT, String.valueOf(port));
        log.info("[RuleManager] Unblocked port: {}", port);
    }

    public boolean isPortBlocked(int port) {
        return blockedPorts.contains(port);
    }

    public List<Integer> getBlockedPorts() {
        return new ArrayList<>(blockedPorts);
    }

    // -----------------------------------------------------------------------
    // Combined check (mirrors C++ RuleManager::shouldBlock)
    // -----------------------------------------------------------------------

    public record BlockReason(RuleType type, String detail) {}

    public Optional<BlockReason> shouldBlock(String srcIp, int dstPort, AppType app, String domain) {
        if (isIpBlocked(srcIp))
            return Optional.of(new BlockReason(RuleType.IP, srcIp));
        if (isPortBlocked(dstPort))
            return Optional.of(new BlockReason(RuleType.PORT, String.valueOf(dstPort)));
        if (app != null && isAppBlocked(app))
            return Optional.of(new BlockReason(RuleType.APP, app.name()));
        if (isDomainBlocked(domain))
            return Optional.of(new BlockReason(RuleType.DOMAIN, domain));
        return Optional.empty();
    }

    // -----------------------------------------------------------------------
    // Rule stats
    // -----------------------------------------------------------------------

    public Map<String, Object> getStats() {
        return Map.of(
                "blockedIps",     blockedIps.size(),
                "blockedApps",    blockedApps.size(),
                "blockedDomains", blockedDomains.size(),
                "blockedPorts",   blockedPorts.size()
        );
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private void persistRule(RuleType type, String value) {
        ruleRepo.findByRuleTypeAndValue(type, value).ifPresentOrElse(
                r -> { r.setActive(true); ruleRepo.save(r); },
                () -> ruleRepo.save(new BlockingRule(type, value))
        );
    }

    private void deactivateRule(RuleType type, String value) {
        ruleRepo.findByRuleTypeAndValue(type, value).ifPresent(r -> {
            r.setActive(false);
            ruleRepo.save(r);
        });
    }

    private void applyToMemory(BlockingRule rule) {
        switch (rule.getRuleType()) {
            case IP     -> blockedIps.add(rule.getValue());
            case APP    -> {
                try { blockedApps.add(AppType.valueOf(rule.getValue())); }
                catch (IllegalArgumentException ignored) {}
            }
            case DOMAIN -> blockedDomains.add(rule.getValue());
            case PORT   -> {
                try { blockedPorts.add(Integer.parseInt(rule.getValue())); }
                catch (NumberFormatException ignored) {}
            }
        }
    }

    /**
     * Wildcard domain matching. Supports patterns like *.facebook.com.
     * Mirrors C++ RuleManager::domainMatchesPattern().
     */
    private static boolean domainMatchesPattern(String domain, String pattern) {
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(2);
            return domain.equals(suffix) || domain.endsWith("." + suffix);
        }
        return domain.equals(pattern) || domain.endsWith("." + pattern);
    }
}
