package com.dpi.model;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe packet/connection statistics.
 * Mirrors DPI::DPIStats in types.h — uses AtomicLong just like std::atomic&lt;uint64_t&gt;.
 */
public class DpiStats {

    public final AtomicLong totalPackets       = new AtomicLong();
    public final AtomicLong totalBytes         = new AtomicLong();
    public final AtomicLong forwardedPackets   = new AtomicLong();
    public final AtomicLong droppedPackets     = new AtomicLong();
    public final AtomicLong tcpPackets         = new AtomicLong();
    public final AtomicLong udpPackets         = new AtomicLong();
    public final AtomicLong otherPackets       = new AtomicLong();
    public final AtomicLong activeConnections  = new AtomicLong();

    @Override
    public String toString() {
        return String.format(
            "Packets[total=%d, fwd=%d, drop=%d] | " +
            "Proto[tcp=%d, udp=%d, other=%d] | " +
            "Bytes=%d | ActiveConns=%d",
            totalPackets.get(), forwardedPackets.get(), droppedPackets.get(),
            tcpPackets.get(), udpPackets.get(), otherPackets.get(),
            totalBytes.get(), activeConnections.get());
    }
}
