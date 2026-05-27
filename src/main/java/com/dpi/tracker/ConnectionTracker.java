package com.dpi.tracker;

import com.dpi.model.*;

import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;

/**
 * Maintains the per-fast-path flow table.
 * Mirrors DPI::ConnectionTracker in connection_tracker.h / connection_tracker.cpp.
 *
 * Each fast-path worker thread owns exactly one ConnectionTracker, so no
 * external locking is needed here (same design as the C++ version where each
 * FP thread has its own tracker).
 */
public class ConnectionTracker {

    private final int    fpId;
    private final int    maxConnections;

    /** The flow table — LinkedHashMap gives us insertion-order iteration
     *  (useful for LRU eviction, same as the C++ evictOldest() strategy). */
    private final LinkedHashMap<FiveTuple, Connection> connections;

    // Aggregate counters
    private long totalSeen       = 0;
    private long classifiedCount = 0;
    private long blockedCount    = 0;

    public ConnectionTracker(int fpId) {
        this(fpId, 100_000);
    }

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId          = fpId;
        this.maxConnections = maxConnections;
        // accessOrder=false → insertion order → oldest first for LRU eviction
        this.connections   = new LinkedHashMap<>(1024, 0.75f, false);
    }

    // ── Core operations ───────────────────────────────────────────────────────

    /**
     * Returns an existing connection for {@code tuple} (or its reverse), or
     * creates a new one.  Mirrors getOrCreateConnection().
     */
    public Connection getOrCreate(FiveTuple tuple) {
        Connection c = connections.get(tuple);
        if (c != null) return c;

        // Check reverse direction
        c = connections.get(tuple.reverse());
        if (c != null) return c;

        // Evict if at capacity — mirrors evictOldest()
        if (connections.size() >= maxConnections) {
            Iterator<FiveTuple> it = connections.keySet().iterator();
            if (it.hasNext()) { it.next(); it.remove(); }
        }

        Connection newConn = new Connection(tuple);
        connections.put(tuple, newConn);
        totalSeen++;
        return newConn;
    }

    /**
     * Returns the connection for {@code tuple} or its reverse, or {@code null}.
     * Mirrors getConnection().
     */
    public Connection get(FiveTuple tuple) {
        Connection c = connections.get(tuple);
        return c != null ? c : connections.get(tuple.reverse());
    }

    /**
     * Updates per-flow statistics for a newly arrived packet.
     * Mirrors updateConnection().
     */
    public void update(Connection conn, int packetSize, boolean isOutbound) {
        if (conn == null) return;
        conn.lastSeen = Instant.now();
        if (isOutbound) { conn.packetsOut++; conn.bytesOut += packetSize; }
        else            { conn.packetsIn++;  conn.bytesIn  += packetSize; }
    }

    /**
     * Marks a connection as classified.
     * Mirrors classifyConnection().
     */
    public void classify(Connection conn, AppType app, String sni) {
        if (conn == null) return;
        if (conn.state != Connection.State.CLASSIFIED) {
            conn.appType = app;
            conn.sni     = sni != null ? sni : "";
            conn.state   = Connection.State.CLASSIFIED;
            classifiedCount++;
        }
    }

    /**
     * Marks a connection as blocked.
     * Mirrors blockConnection().
     */
    public void block(Connection conn) {
        if (conn == null) return;
        conn.state  = Connection.State.BLOCKED;
        conn.action = Connection.Action.DROP;
        blockedCount++;
    }

    /**
     * Marks a connection as closed and removes it.
     * Mirrors closeConnection().
     */
    public void close(FiveTuple tuple) {
        Connection c = connections.remove(tuple);
        if (c == null) connections.remove(tuple.reverse());
    }

    /**
     * Removes connections whose {@code lastSeen} is older than {@code timeoutSeconds}.
     * Mirrors cleanupStale().
     *
     * @return number of connections removed
     */
    public int cleanupStale(long timeoutSeconds) {
        Instant cutoff = Instant.now().minusSeconds(timeoutSeconds);
        int removed = 0;
        Iterator<Map.Entry<FiveTuple, Connection>> it = connections.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getValue().lastSeen.isBefore(cutoff)) {
                it.remove();
                removed++;
            }
        }
        return removed;
    }

    /**
     * Iterates over all active connections.
     * Mirrors forEach().
     */
    public void forEach(Consumer<Connection> action) {
        connections.values().forEach(action);
    }

    /** Returns a snapshot list of all connections. Mirrors getAllConnections(). */
    public List<Connection> getAll() {
        return new ArrayList<>(connections.values());
    }

    public int getActiveCount() { return connections.size(); }

    // ── Statistics ────────────────────────────────────────────────────────────

    public record Stats(int activeConnections, long totalSeen,
                        long classifiedCount, long blockedCount) {}

    public Stats getStats() {
        return new Stats(connections.size(), totalSeen, classifiedCount, blockedCount);
    }

    public void clear() {
        connections.clear();
        totalSeen = classifiedCount = blockedCount = 0;
    }

    public int getFpId() { return fpId; }
}
