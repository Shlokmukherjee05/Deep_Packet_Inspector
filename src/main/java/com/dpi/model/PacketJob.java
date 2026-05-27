package com.dpi.model;

/**
 * Packet wrapper passed between pipeline stages (LB → FP → output).
 * Mirrors DPI::PacketJob in types.h.
 */
public class PacketJob {

    public int    packetId;
    public FiveTuple tuple;
    public byte[] data;

    // Offsets within data[]
    public int ethOffset;
    public int ipOffset;
    public int transportOffset;
    public int payloadOffset;
    public int payloadLength;

    public int  tcpFlags;

    // Timestamps from PCAP header
    public long tsSec;
    public long tsUsec;
}
