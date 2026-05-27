package com.dpi.engine;

import com.dpi.core.PacketParser;
import com.dpi.core.PcapReader;
import com.dpi.model.*;
import com.dpi.rules.RuleManager;
import com.dpi.tracker.ConnectionTracker;
import com.dpi.tracker.GlobalConnectionTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Top-level DPI engine — orchestrates reader, load balancers, fast-path
 * workers, and output writer.
 *
 * Architecture (mirrors dpi_engine.h diagram):
 *
 *   PcapReader  →  [LB-0, LB-1, …]  →  [FP-0 … FP-N]  →  output queue  →  PcapWriter
 *
 * All threading mirrors the C++ DPIEngine in dpi_engine.cpp.
 */
public class DpiEngine {

    private static final Logger log = LoggerFactory.getLogger(DpiEngine.class);

    // ── Configuration record (mirrors DPIEngine::Config) ─────────────────────

    public record Config(
        int    numLoadBalancers,
        int    fpsPerLb,
        int    queueSize,
        String rulesFile,
        boolean verbose
    ) {
        /** Sensible defaults matching the C++ defaults */
        public static Config defaults() {
            return new Config(2, 2, 10_000, null, false);
        }
    }

    // ── Engine components ─────────────────────────────────────────────────────

    private final Config                  config;
    private final RuleManager             ruleManager     = new RuleManager();
    private final GlobalConnectionTable   globalConnTable = new GlobalConnectionTable();
    private final DpiStats                stats           = new DpiStats();

    private List<FastPathProcessor>       fastPaths;
    private List<LoadBalancer>            loadBalancers;
    private Thread                        outputThread;
    private Thread                        readerThread;

    private final BlockingQueue<PacketJob>        outputQueue;
    private final PcapWriter                      writer = new PcapWriter();
    private final AtomicInteger                   packetCounter = new AtomicInteger(0);

    private volatile boolean running           = false;
    private volatile boolean processingDone    = false;

    public DpiEngine(Config config) {
        this.config      = config;
        this.outputQueue = new LinkedBlockingQueue<>(config.queueSize());
        printBanner();
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /**
     * Initialises all sub-components.
     * Mirrors DPIEngine::initialize().
     */
    public boolean initialize() {
        if (config.rulesFile() != null) {
            ruleManager.loadRules(Path.of(config.rulesFile()));
        }

        int totalFps = config.numLoadBalancers() * config.fpsPerLb();

        // Create fast-path processors
        fastPaths = new ArrayList<>(totalFps);
        for (int i = 0; i < totalFps; i++) {
            FastPathProcessor fp = new FastPathProcessor(
                i,
                config.queueSize(),
                ruleManager,
                this::handleOutput
            );
            fastPaths.add(fp);
            globalConnTable.registerTracker(fp.getConnectionTracker());
        }

        // Create load balancers; assign a slice of FP workers to each LB
        loadBalancers = new ArrayList<>(config.numLoadBalancers());
        for (int i = 0; i < config.numLoadBalancers(); i++) {
            int from = i * config.fpsPerLb();
            int to   = from + config.fpsPerLb();
            List<FastPathProcessor> myFps = fastPaths.subList(from, to);
            loadBalancers.add(new LoadBalancer(i, config.queueSize(), myFps));
        }

        log.info("DpiEngine initialised — LBs={} FPs={}", config.numLoadBalancers(), totalFps);
        return true;
    }

    /**
     * Starts all worker threads.
     * Mirrors DPIEngine::start().
     */
    public void start() {
        if (running) return;
        running = true;
        processingDone = false;

        fastPaths.forEach(FastPathProcessor::start);
        loadBalancers.forEach(LoadBalancer::start);

        outputThread = new Thread(this::outputThreadFunc, "OutputWriter");
        outputThread.setDaemon(true);
        outputThread.start();

        log.info("All DPI threads started");
    }

    /**
     * Stops all worker threads.
     * Mirrors DPIEngine::stop().
     */
    public void stop() {
        if (!running) return;
        running = false;

        loadBalancers.forEach(LoadBalancer::stop);
        fastPaths.forEach(FastPathProcessor::stop);

        if (outputThread != null) outputThread.interrupt();
    }

    /**
     * Reads {@code inputFile}, processes every packet, writes forwarded traffic
     * to {@code outputFile}.
     * Mirrors DPIEngine::processFile().
     */
    public boolean processFile(Path inputFile, Path outputFile) {
        try {
            writer.open(outputFile);
        } catch (IOException e) {
            log.error("Cannot open output file {}: {}", outputFile, e.getMessage());
            return false;
        }

        start();

        readerThread = new Thread(() -> readerThreadFunc(inputFile), "PcapReader");
        readerThread.start();

        waitForCompletion();
        return true;
    }

    /** Blocks until the reader thread finishes and all queues drain. */
    public void waitForCompletion() {
        try {
            if (readerThread != null) readerThread.join();

            // Drain remaining packets through FPs — allow up to 5 s
            long deadline = System.currentTimeMillis() + 5_000;
            while (!allQueuesEmpty() && System.currentTimeMillis() < deadline) {
                Thread.sleep(50);
            }

            stop();
            if (outputThread != null) outputThread.join(3_000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            try { writer.close(); } catch (IOException ignored) {}
        }
    }

    // ── Internal threads ──────────────────────────────────────────────────────

    /** Reads packets from a PCAP file and distributes them to load balancers. */
    private void readerThreadFunc(Path inputFile) {
        try (PcapReader reader = new PcapReader()) {
            reader.open(inputFile);

            RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                ParsedPacket parsed = PacketParser.parse(raw);
                if (parsed == null) continue;

                PacketJob job = createJob(raw, parsed);
                stats.totalPackets.incrementAndGet();
                stats.totalBytes.addAndGet(raw.data.length);

                updateProtoStats(parsed);

                // Round-robin across load balancers (top-level distribution)
                int lbIdx = (int) (stats.totalPackets.get() % loadBalancers.size());
                BlockingQueue<PacketJob> lbQ = loadBalancers.get(lbIdx).getQueue();
                try {
                    if (!lbQ.offer(job, 200, TimeUnit.MILLISECONDS)) {
                        log.warn("LB queue full — dropping packet #{}", job.packetId);
                        stats.droppedPackets.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        } catch (IOException e) {
            log.error("Reader error: {}", e.getMessage());
        }
        log.info("Reader finished. Total packets: {}", stats.totalPackets.get());
    }

    /** Drains the output queue and writes forwarded packets to disk. */
    private void outputThreadFunc() {
        while (running || !outputQueue.isEmpty()) {
            try {
                PacketJob job = outputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job != null) {
                    try { writer.writePacket(job); }
                    catch (IOException e) { log.warn("Write error: {}", e.getMessage()); }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    /** Called by each FP after making a forwarding decision. */
    private void handleOutput(PacketJob job, Connection.Action action) {
        if (action == Connection.Action.FORWARD || action == Connection.Action.LOG_ONLY) {
            stats.forwardedPackets.incrementAndGet();
            outputQueue.offer(job);
        } else {
            stats.droppedPackets.incrementAndGet();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private PacketJob createJob(RawPacket raw, ParsedPacket parsed) {
        PacketJob job = new PacketJob();
        job.packetId      = packetCounter.incrementAndGet();
        job.data          = raw.data;
        job.tsSec         = raw.tsSec;
        job.tsUsec        = raw.tsUsec;
        job.payloadOffset = parsed.payloadOffset;
        job.payloadLength = parsed.payloadLength;
        job.tcpFlags      = parsed.tcpFlags;

        if (parsed.hasIp) {
            try {
                int srcIp   = com.dpi.model.FiveTuple.parseIp(parsed.srcIp);
                int dstIp   = com.dpi.model.FiveTuple.parseIp(parsed.dstIp);
                short sport = (short) parsed.srcPort;
                short dport = (short) parsed.dstPort;
                byte  proto = (byte)  parsed.protocol;
                job.tuple = new FiveTuple(srcIp, dstIp, sport, dport, proto);
            } catch (Exception e) {
                job.tuple = null;
            }
        }
        return job;
    }

    private void updateProtoStats(ParsedPacket p) {
        if (!p.hasIp) return;
        switch (p.protocol) {
            case PacketParser.PROTO_TCP  -> stats.tcpPackets.incrementAndGet();
            case PacketParser.PROTO_UDP  -> stats.udpPackets.incrementAndGet();
            default                      -> stats.otherPackets.incrementAndGet();
        }
    }

    private boolean allQueuesEmpty() {
        return loadBalancers.stream().allMatch(lb -> lb.getQueue().isEmpty())
            && fastPaths.stream().allMatch(fp -> fp.getQueue().isEmpty());
    }

    // ── Rule management delegation ────────────────────────────────────────────

    public void blockIp(String ip)        { ruleManager.blockIp(ip); }
    public void unblockIp(String ip)      { ruleManager.unblockIp(ip); }
    public void blockApp(AppType app)     { ruleManager.blockApp(app); }
    public void unblockApp(AppType app)   { ruleManager.unblockApp(app); }
    public void blockDomain(String d)     { ruleManager.blockDomain(d); }
    public void unblockDomain(String d)   { ruleManager.unblockDomain(d); }
    public boolean loadRules(Path p)      { return ruleManager.loadRules(p); }
    public boolean saveRules(Path p)      { return ruleManager.saveRules(p); }
    public RuleManager getRuleManager()   { return ruleManager; }

    // ── Reporting ─────────────────────────────────────────────────────────────

    public DpiStats getStats()            { return stats; }
    public boolean  isRunning()           { return running; }

    public String generateReport() {
        var rs  = ruleManager.getStats();
        return String.format("""
            ╔══════════════════════════════════════════════════════════════╗
            ║                      DPI ENGINE REPORT                      ║
            ╠══════════════════════════════════════════════════════════════╣
            ║ Packets processed : %-6d                                   ║
            ║ Packets forwarded : %-6d                                   ║
            ║ Packets dropped   : %-6d                                   ║
            ║ TCP / UDP / Other : %d / %d / %d
            ║ Total bytes       : %-10d                               ║
            ╠══════════════════════════════════════════════════════════════╣
            ║ Rules  IPs:%-3d  Apps:%-3d  Domains:%-3d  Ports:%-3d         ║
            ╚══════════════════════════════════════════════════════════════╝
            """,
            stats.totalPackets.get(),
            stats.forwardedPackets.get(),
            stats.droppedPackets.get(),
            stats.tcpPackets.get(), stats.udpPackets.get(), stats.otherPackets.get(),
            stats.totalBytes.get(),
            rs.blockedIps(), rs.blockedApps(), rs.blockedDomains(), rs.blockedPorts()
        ) + globalConnTable.generateReport();
    }

    public String generateClassificationReport() {
        return globalConnTable.generateReport();
    }

    public void printStatus() {
        log.info("{}", stats);
    }

    // ── Banner ────────────────────────────────────────────────────────────────

    private void printBanner() {
        System.out.println("""
            ╔══════════════════════════════════════════════════════════════╗
            ║                    DPI ENGINE v1.0  (Java)                   ║
            ║               Deep Packet Inspection System                   ║
            ╠══════════════════════════════════════════════════════════════╣""");
        System.out.printf("║   Load Balancers : %-3d                                         ║%n", config.numLoadBalancers());
        System.out.printf("║   FPs per LB     : %-3d                                         ║%n", config.fpsPerLb());
        System.out.printf("║   Total FP threads: %-3d                                        ║%n", config.numLoadBalancers() * config.fpsPerLb());
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }
}
