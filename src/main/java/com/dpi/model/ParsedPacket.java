package com.dpi.model;

/**
 * Human-readable representation of a parsed network packet.
 * Mirrors PacketAnalyzer::ParsedPacket in packet_parser.h.
 */
public class ParsedPacket {

    // ── Timestamps ────────────────────────────────────────────────────────────
    public long tsSec;
    public long tsUsec;

    // ── Ethernet layer ────────────────────────────────────────────────────────
    public String srcMac;
    public String dstMac;
    public int    etherType;   // 0x0800 = IPv4, 0x86DD = IPv6, 0x0806 = ARP

    // ── IP layer ──────────────────────────────────────────────────────────────
    public boolean hasIp    = false;
    public int     ipVersion;
    public String  srcIp;
    public String  dstIp;
    public int     protocol; // 6 = TCP, 17 = UDP, 1 = ICMP
    public int     ttl;

    // ── Transport layer ───────────────────────────────────────────────────────
    public boolean hasTcp  = false;
    public boolean hasUdp  = false;
    public int     srcPort;
    public int     dstPort;

    // ── TCP-specific ──────────────────────────────────────────────────────────
    public int  tcpFlags;
    public long seqNumber;
    public long ackNumber;

    // ── Payload ───────────────────────────────────────────────────────────────
    public int    payloadLength;
    /** Offset into {@link #rawData} where the payload starts */
    public int    payloadOffset;
    /** Reference to the full packet byte array (avoids copying) */
    public byte[] rawData;

    // ── EtherType constants ───────────────────────────────────────────────────
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_ARP  = 0x0806;

    // ── TCP flag constants ────────────────────────────────────────────────────
    public static final int TCP_FIN = 0x01;
    public static final int TCP_SYN = 0x02;
    public static final int TCP_RST = 0x04;
    public static final int TCP_PSH = 0x08;
    public static final int TCP_ACK = 0x10;
    public static final int TCP_URG = 0x20;
}
