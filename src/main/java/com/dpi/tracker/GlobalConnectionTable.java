package com.dpi.tracker;

import com.dpi.model.AppType;
import com.dpi.model.Connection;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Aggregates per-FP {@link ConnectionTracker} statistics for reporting.
 * Mirrors DPI::GlobalConnectionTable in connection_tracker.h / connection_tracker.cpp.
 *
 * Thread-safe for concurrent registration and read; individual trackers are
 * accessed without locking (they are owned by their FP thread).
 */
public class GlobalConnectionTable {

    private final List<ConnectionTracker> trackers = new CopyOnWriteArrayList<>();

    public void registerTracker(ConnectionTracker tracker) {
        trackers.add(tracker);
    }

    // ── Aggregated stats record ───────────────────────────────────────────────

    public record GlobalStats(
        long totalActiveConnections,
        long totalConnectionsSeen,
        Map<AppType, Long> appDistribution,
        List<Map.Entry<String, Long>> topDomains
    ) {}

    /**
     * Computes aggregate stats across all registered trackers.
     * Mirrors GlobalConnectionTable::getGlobalStats().
     */
    public GlobalStats getGlobalStats() {
        long totalActive = 0;
        long totalSeen   = 0;
        Map<AppType, Long> appDist  = new EnumMap<>(AppType.class);
        Map<String, Long>  domainCt = new HashMap<>();

        for (ConnectionTracker t : trackers) {
            var stats = t.getStats();
            totalActive += stats.activeConnections();
            totalSeen   += stats.totalSeen();

            for (Connection c : t.getAll()) {
                if (c.appType != AppType.UNKNOWN) {
                    appDist.merge(c.appType, 1L, Long::sum);
                }
                if (!c.sni.isEmpty()) {
                    domainCt.merge(c.sni, 1L, Long::sum);
                }
            }
        }

        // Top-10 domains by connection count
        List<Map.Entry<String, Long>> topDomains = new ArrayList<>(domainCt.entrySet());
        topDomains.sort(Map.Entry.<String, Long>comparingByValue().reversed());
        if (topDomains.size() > 10) topDomains = topDomains.subList(0, 10);

        return new GlobalStats(totalActive, totalSeen, appDist, topDomains);
    }

    /**
     * Generates a human-readable classification report.
     * Mirrors GlobalConnectionTable::generateReport().
     */
    public String generateReport() {
        GlobalStats stats = getGlobalStats();
        StringBuilder sb = new StringBuilder();

        sb.append("\n╔══════════════════════════════════════════════╗\n");
        sb.append(  "║         CLASSIFICATION REPORT                ║\n");
        sb.append(  "╚══════════════════════════════════════════════╝\n");
        sb.append(String.format("Active connections : %d%n", stats.totalActiveConnections()));
        sb.append(String.format("Total seen         : %d%n", stats.totalConnectionsSeen()));

        sb.append("\nApplication Distribution:\n");
        stats.appDistribution()
             .entrySet().stream()
             .sorted(Map.Entry.<AppType, Long>comparingByValue().reversed())
             .forEach(e -> sb.append(
                 String.format("  %-15s : %d%n", e.getKey().label(), e.getValue())));

        sb.append("\nTop Domains:\n");
        for (var entry : stats.topDomains()) {
            sb.append(String.format("  %-40s : %d%n", entry.getKey(), entry.getValue()));
        }

        return sb.toString();
    }
}
