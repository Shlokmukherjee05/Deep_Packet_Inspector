package com.dpi.rules;

import com.dpi.model.AppType;
import com.dpi.model.FiveTuple;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Thread-safe container for packet-filtering rules.
 * Mirrors DPI::RuleManager in rule_manager.h / rule_manager.cpp.
 *
 * Rule categories:
 *   1. IP-based  — block specific source IPs
 *   2. App-based — block applications identified via SNI
 *   3. Domain-based — block domains / wildcard patterns (*.example.com)
 *   4. Port-based — block destination ports
 *
 * Java's {@link ReentrantReadWriteLock} replaces C++ std::shared_mutex;
 * the read/write semantics are identical.
 */
public class RuleManager {

    private static final Logger log = LoggerFactory.getLogger(RuleManager.class);

    // ── IP blocking ───────────────────────────────────────────────────────────
    private final ReadWriteLock ipLock     = new ReentrantReadWriteLock();
    private final Set<Integer>  blockedIps = new HashSet<>();

    // ── App blocking ──────────────────────────────────────────────────────────
    private final ReadWriteLock  appLock     = new ReentrantReadWriteLock();
    private final Set<AppType>   blockedApps = new HashSet<>();

    // ── Domain blocking ───────────────────────────────────────────────────────
    private final ReadWriteLock  domainLock     = new ReentrantReadWriteLock();
    private final Set<String>    blockedDomains = new HashSet<>();
    private final List<String>   domainPatterns = new ArrayList<>(); // wildcard patterns

    // ── Port blocking ─────────────────────────────────────────────────────────
    private final ReadWriteLock   portLock     = new ReentrantReadWriteLock();
    private final Set<Integer>    blockedPorts = new HashSet<>();

    // =========================================================================
    // IP blocking — mirrors RuleManager::blockIP / unblockIP / isIPBlocked
    // =========================================================================

    public void blockIp(int ip) {
        ipLock.writeLock().lock();
        try   { blockedIps.add(ip); }
        finally { ipLock.writeLock().unlock(); }
        log.info("Blocked IP: {}", FiveTuple.ipToString(ip));
    }

    public void blockIp(String ip) { blockIp(FiveTuple.parseIp(ip)); }

    public void unblockIp(int ip) {
        ipLock.writeLock().lock();
        try   { blockedIps.remove(ip); }
        finally { ipLock.writeLock().unlock(); }
        log.info("Unblocked IP: {}", FiveTuple.ipToString(ip));
    }

    public void unblockIp(String ip) { unblockIp(FiveTuple.parseIp(ip)); }

    public boolean isIpBlocked(int ip) {
        ipLock.readLock().lock();
        try   { return blockedIps.contains(ip); }
        finally { ipLock.readLock().unlock(); }
    }

    public List<String> getBlockedIps() {
        ipLock.readLock().lock();
        try {
            List<String> list = new ArrayList<>(blockedIps.size());
            for (int ip : blockedIps) list.add(FiveTuple.ipToString(ip));
            return list;
        } finally { ipLock.readLock().unlock(); }
    }

    // =========================================================================
    // App blocking — mirrors blockApp / unblockApp / isAppBlocked
    // =========================================================================

    public void blockApp(AppType app) {
        appLock.writeLock().lock();
        try   { blockedApps.add(app); }
        finally { appLock.writeLock().unlock(); }
        log.info("Blocked app: {}", app.label());
    }

    public void blockApp(String appName) {
        try { blockApp(AppType.valueOf(appName.toUpperCase(Locale.ROOT))); }
        catch (IllegalArgumentException e) {
            log.warn("Unknown app name: {}", appName);
        }
    }

    public void unblockApp(AppType app) {
        appLock.writeLock().lock();
        try   { blockedApps.remove(app); }
        finally { appLock.writeLock().unlock(); }
        log.info("Unblocked app: {}", app.label());
    }

    public boolean isAppBlocked(AppType app) {
        appLock.readLock().lock();
        try   { return blockedApps.contains(app); }
        finally { appLock.readLock().unlock(); }
    }

    public List<AppType> getBlockedApps() {
        appLock.readLock().lock();
        try   { return new ArrayList<>(blockedApps); }
        finally { appLock.readLock().unlock(); }
    }

    // =========================================================================
    // Domain blocking — mirrors blockDomain / isDomainBlocked
    // =========================================================================

    /**
     * Blocks a domain or wildcard pattern (e.g. {@code *.facebook.com}).
     * Mirrors RuleManager::blockDomain().
     */
    public void blockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.startsWith("*.")) {
                domainPatterns.add(domain.substring(2)); // store suffix
            } else {
                blockedDomains.add(domain.toLowerCase(Locale.ROOT));
            }
        } finally { domainLock.writeLock().unlock(); }
        log.info("Blocked domain: {}", domain);
    }

    public void unblockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.startsWith("*.")) {
                domainPatterns.remove(domain.substring(2));
            } else {
                blockedDomains.remove(domain.toLowerCase(Locale.ROOT));
            }
        } finally { domainLock.writeLock().unlock(); }
    }

    /**
     * Checks whether a domain (exact or via wildcard suffix) is blocked.
     * Mirrors RuleManager::isDomainBlocked().
     */
    public boolean isDomainBlocked(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        String lower = domain.toLowerCase(Locale.ROOT);
        domainLock.readLock().lock();
        try {
            if (blockedDomains.contains(lower)) return true;
            for (String pattern : domainPatterns) {
                if (lower.endsWith(pattern) || lower.equals(pattern.substring(pattern.indexOf('.') + 1))) {
                    return true;
                }
            }
            return false;
        } finally { domainLock.readLock().unlock(); }
    }

    public List<String> getBlockedDomains() {
        domainLock.readLock().lock();
        try {
            List<String> list = new ArrayList<>(blockedDomains);
            for (String p : domainPatterns) list.add("*." + p);
            return list;
        } finally { domainLock.readLock().unlock(); }
    }

    // =========================================================================
    // Port blocking — mirrors blockPort / isPortBlocked
    // =========================================================================

    public void blockPort(int port) {
        portLock.writeLock().lock();
        try   { blockedPorts.add(port); }
        finally { portLock.writeLock().unlock(); }
        log.info("Blocked port: {}", port);
    }

    public void unblockPort(int port) {
        portLock.writeLock().lock();
        try   { blockedPorts.remove(port); }
        finally { portLock.writeLock().unlock(); }
    }

    public boolean isPortBlocked(int port) {
        portLock.readLock().lock();
        try   { return blockedPorts.contains(port); }
        finally { portLock.readLock().unlock(); }
    }

    // =========================================================================
    // Combined check — mirrors RuleManager::shouldBlock()
    // =========================================================================

    public record BlockReason(Type type, String detail) {
        public enum Type { IP, APP, DOMAIN, PORT }
    }

    /**
     * Returns the first matching block reason, or {@code Optional.empty()} if allowed.
     * Mirrors RuleManager::shouldBlock().
     */
    public Optional<BlockReason> shouldBlock(int srcIp, int dstPort, AppType app, String domain) {
        if (isIpBlocked(srcIp))
            return Optional.of(new BlockReason(BlockReason.Type.IP, FiveTuple.ipToString(srcIp)));
        if (isPortBlocked(dstPort))
            return Optional.of(new BlockReason(BlockReason.Type.PORT, String.valueOf(dstPort)));
        if (app != AppType.UNKNOWN && isAppBlocked(app))
            return Optional.of(new BlockReason(BlockReason.Type.APP, app.label()));
        if (domain != null && isDomainBlocked(domain))
            return Optional.of(new BlockReason(BlockReason.Type.DOMAIN, domain));
        return Optional.empty();
    }

    // =========================================================================
    // Persistence — mirrors saveRules / loadRules
    // =========================================================================

    /** File format mirrors the C++ rules file: one directive per line. */
    public boolean saveRules(Path path) {
        try (BufferedWriter w = Files.newBufferedWriter(path)) {
            for (String ip     : getBlockedIps())     { w.write("block_ip "     + ip);     w.newLine(); }
            for (AppType app   : getBlockedApps())    { w.write("block_app "    + app);    w.newLine(); }
            for (String domain : getBlockedDomains()) { w.write("block_domain " + domain); w.newLine(); }
            portLock.readLock().lock();
            try {
                for (int port : blockedPorts) { w.write("block_port " + port); w.newLine(); }
            } finally { portLock.readLock().unlock(); }
            return true;
        } catch (IOException e) {
            log.error("Failed to save rules to {}: {}", path, e.getMessage());
            return false;
        }
    }

    public boolean loadRules(Path path) {
        try (BufferedReader r = Files.newBufferedReader(path)) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.strip();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] parts = line.split("\\s+", 2);
                if (parts.length < 2) continue;
                switch (parts[0].toLowerCase(Locale.ROOT)) {
                    case "block_ip"     -> blockIp(parts[1]);
                    case "block_app"    -> blockApp(parts[1]);
                    case "block_domain" -> blockDomain(parts[1]);
                    case "block_port"   -> blockPort(Integer.parseInt(parts[1]));
                    default -> log.warn("Unknown rule directive: {}", parts[0]);
                }
            }
            return true;
        } catch (IOException e) {
            log.error("Failed to load rules from {}: {}", path, e.getMessage());
            return false;
        }
    }

    public void clearAll() {
        ipLock.writeLock().lock();     try { blockedIps.clear();     } finally { ipLock.writeLock().unlock(); }
        appLock.writeLock().lock();    try { blockedApps.clear();    } finally { appLock.writeLock().unlock(); }
        domainLock.writeLock().lock(); try { blockedDomains.clear(); domainPatterns.clear(); } finally { domainLock.writeLock().unlock(); }
        portLock.writeLock().lock();   try { blockedPorts.clear();   } finally { portLock.writeLock().unlock(); }
    }

    // =========================================================================
    // Statistics — mirrors RuleManager::getStats()
    // =========================================================================

    public record RuleStats(int blockedIps, int blockedApps, int blockedDomains, int blockedPorts) {}

    public RuleStats getStats() {
        ipLock.readLock().lock();
        int ips = blockedIps.size();
        ipLock.readLock().unlock();

        appLock.readLock().lock();
        int apps = blockedApps.size();
        appLock.readLock().unlock();

        domainLock.readLock().lock();
        int domains = blockedDomains.size() + domainPatterns.size();
        domainLock.readLock().unlock();

        portLock.readLock().lock();
        int ports = blockedPorts.size();
        portLock.readLock().unlock();

        return new RuleStats(ips, apps, domains, ports);
    }
}
