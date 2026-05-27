package com.dpi.engine;

import com.dpi.core.SniExtractor;
import com.dpi.model.*;
import com.dpi.rules.RuleManager;
import com.dpi.tracker.ConnectionTracker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

/**
 * Fast-path packet processor.
 * Mirrors the FP (fast-path) thread concept from fast_path.cpp/h.
 *
 * Each FastPathProcessor:
 *   - Runs in its own thread
 *   - Owns a {@link ConnectionTracker}
 *   - Classifies flows via SNI / port heuristics
 *   - Applies {@link RuleManager} rules
 *   - Invokes an output callback with the forwarding decision
 */
public class FastPathProcessor implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(FastPathProcessor.class);

    private final int fpId;
    private final BlockingQueue<PacketJob> inQueue;
    private final RuleManager             ruleManager;
    private final BiConsumer<PacketJob, Connection.Action> outputCallback;
    private final ConnectionTracker       tracker;

    private volatile boolean running = false;
    private Thread thread;

    // Port-based classification heuristics (mirrors fast_path.cpp logic)
    private static final int PORT_DNS   = 53;
    private static final int PORT_HTTP  = 80;
    private static final int PORT_HTTPS = 443;
    private static final int PORT_QUIC  = 443; // QUIC also on 443 (UDP)

    public FastPathProcessor(int fpId,
                             int queueCapacity,
                             RuleManager ruleManager,
                             BiConsumer<PacketJob, Connection.Action> outputCallback) {
        this.fpId           = fpId;
        this.ruleManager    = ruleManager;
        this.outputCallback = outputCallback;
        this.inQueue        = new LinkedBlockingQueue<>(queueCapacity);
        this.tracker        = new ConnectionTracker(fpId);
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public void start() {
        running = true;
        thread  = new Thread(this, "FastPath-" + fpId);
        thread.setDaemon(true);
        thread.start();
    }

    public void stop() {
        running = false;
        if (thread != null) thread.interrupt();
    }

    public void join() throws InterruptedException {
        if (thread != null) thread.join(5000);
    }

    /** Enqueues a packet job for this processor. Returns false if queue is full. */
    public boolean enqueue(PacketJob job) {
        return inQueue.offer(job);
    }

    public BlockingQueue<PacketJob> getQueue() { return inQueue; }
    public ConnectionTracker getConnectionTracker() { return tracker; }

    // ── Main loop ─────────────────────────────────────────────────────────────

    @Override
    public void run() {
        log.debug("FastPath-{} started", fpId);
        while (running || !inQueue.isEmpty()) {
            try {
                PacketJob job = inQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job != null) processPacket(job);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        log.debug("FastPath-{} stopped", fpId);
    }

    // ── Packet processing ─────────────────────────────────────────────────────

    private void processPacket(PacketJob job) {
        if (job.tuple == null) return;

        Connection conn = tracker.getOrCreate(job.tuple);
        tracker.update(conn, job.data != null ? job.data.length : 0, true);

        // ── Step 1: classify the flow if not yet done ──────────────────────
        if (conn.state == Connection.State.NEW || conn.state == Connection.State.ESTABLISHED) {
            classifyConnection(conn, job);
        }

        // ── Step 2: check rules ────────────────────────────────────────────
        Connection.Action action = conn.action;

        if (conn.state != Connection.State.BLOCKED) {
            int  srcIp = job.tuple.srcIp;
            int  dstPort = Short.toUnsignedInt(job.tuple.dstPort);
            var  blockReason = ruleManager.shouldBlock(srcIp, dstPort, conn.appType, conn.sni);

            if (blockReason.isPresent()) {
                tracker.block(conn);
                action = Connection.Action.DROP;
                if (log.isDebugEnabled()) {
                    log.debug("FP-{} DROP packet #{} reason={} detail={}",
                        fpId, job.packetId,
                        blockReason.get().type(), blockReason.get().detail());
                }
            } else {
                action = Connection.Action.FORWARD;
            }
        } else {
            action = Connection.Action.DROP;
        }

        // ── Step 3: emit to output ─────────────────────────────────────────
        outputCallback.accept(job, action);
    }

    private void classifyConnection(Connection conn, PacketJob job) {
        if (job.tuple == null) return;

        int dstPort = Short.toUnsignedInt(job.tuple.dstPort);
        int srcPort = Short.toUnsignedInt(job.tuple.srcPort);
        int proto   = Byte.toUnsignedInt(job.tuple.protocol);

        // DNS
        if (dstPort == PORT_DNS || srcPort == PORT_DNS) {
            tracker.classify(conn, AppType.DNS, "");
            return;
        }

        // HTTP (plain)
        if (dstPort == PORT_HTTP && proto == FiveTuple.PROTO_TCP) {
            tracker.classify(conn, AppType.HTTP, "");
            return;
        }

        // TLS / HTTPS — try to extract SNI from the payload
        if (dstPort == PORT_HTTPS && proto == FiveTuple.PROTO_TCP) {
            String sni = null;
            if (job.data != null && job.payloadLength > 0) {
                sni = SniExtractor.extract(job.data, job.payloadOffset, job.payloadLength);
            }
            if (sni != null && !sni.isEmpty()) {
                AppType app = AppType.fromSni(sni);
                tracker.classify(conn, app, sni);
            } else {
                tracker.classify(conn, AppType.TLS, "");
            }
            return;
        }

        // QUIC (UDP on 443)
        if (dstPort == PORT_QUIC && proto == FiveTuple.PROTO_UDP) {
            tracker.classify(conn, AppType.QUIC, "");
            return;
        }

        // Advance to ESTABLISHED if we have seen packets but can't classify yet
        if (conn.state == Connection.State.NEW) {
            conn.state = Connection.State.ESTABLISHED;
        }
    }
}
