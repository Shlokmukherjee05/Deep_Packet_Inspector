package com.dpi.model;

/**
 * Raw bytes of a single captured packet, as read from a PCAP file.
 * Mirrors PacketAnalyzer::RawPacket in pcap_reader.h.
 */
public class RawPacket {
    /** Timestamp seconds (epoch) */
    public long tsSec;
    /** Timestamp microseconds */
    public long tsUsec;
    /** Bytes stored in the file (may be truncated to snaplen) */
    public int inclLen;
    /** Original on-wire length */
    public int origLen;
    /** Raw packet bytes */
    public byte[] data;
}
