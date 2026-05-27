package com.dpi.engine;

import com.dpi.model.PacketJob;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Load balancer — distributes packets to fast-path workers using a
 * consistent hash of the five-tuple (same connection always lands on the
 * same FP worker, ensuring ordered per-flow processing).
 *
 * Mirrors DPI::LoadBalancer in load_balancer.cpp/h.
 */
public class LoadBalancer implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(LoadBalancer.class);

    private final int lbId;
    private final BlockingQueue<PacketJob>        inQueue;
    private final List<FastPathProcessor>         fastPaths;

    private volatile boolean running = false;
    private Thread thread;

    public LoadBalancer(int lbId,
                        int queueCapacity,
                        List<FastPathProcessor> fastPaths) {
        this.lbId      = lbId;
        this.fastPaths = fastPaths;
        this.inQueue   = new LinkedBlockingQueue<>(queueCapacity);
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public void start() {
        running = true;
        thread  = new Thread(this, "LoadBalancer-" + lbId);
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

    /** Returns the queue into which packets should be placed for this LB. */
    public BlockingQueue<PacketJob> getQueue() { return inQueue; }

    // ── Main loop ─────────────────────────────────────────────────────────────

    @Override
    public void run() {
        log.debug("LoadBalancer-{} started (FPs: {})", lbId, fastPaths.size());
        while (running || !inQueue.isEmpty()) {
            try {
                PacketJob job = inQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job != null) dispatch(job);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        log.debug("LoadBalancer-{} stopped", lbId);
    }

    // ── Dispatch ──────────────────────────────────────────────────────────────

    /**
     * Consistently hashes the five-tuple to select a fast-path worker.
     * Mirrors LB's hash-based dispatch in load_balancer.cpp.
     */
    private void dispatch(PacketJob job) {
        int fpIdx = selectFastPath(job);
        FastPathProcessor fp = fastPaths.get(fpIdx);

        // Try to enqueue; on failure just drop (mirrors queue-full behavior in C++)
        if (!fp.enqueue(job)) {
            log.warn("LB-{}: FP-{} queue full, dropping packet #{}", lbId, fpIdx, job.packetId);
        }
    }

    /**
     * Returns the index into {@link #fastPaths} for this packet.
     * Uses the five-tuple hash for connection affinity.
     */
    private int selectFastPath(PacketJob job) {
        if (job.tuple == null || fastPaths.size() == 1) return 0;
        int h = job.tuple.hashCode();
        return Math.abs(h) % fastPaths.size();
    }
}
