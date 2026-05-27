package com.dpi.core;

import com.dpi.model.ParsedPacket;
import com.dpi.model.RawPacket;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Parses raw packet bytes into a human-readable {@link ParsedPacket}.
 * Mirrors PacketAnalyzer::PacketParser in packet_parser.h / packet_parser.cpp.
 *
 * All byte-order conversion is handled by {@link ByteBuffer} with
 * {@link ByteOrder#BIG_ENDIAN} (network order), replacing the C++
 * PortableNet::netToHost16/32 helpers from platform.h.
 */
public class PacketParser {

    // ── Protocol numbers — mirrors packet_parser.h Protocol namespace ─────────
    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP  = 6;
    public static final int PROTO_UDP  = 17;

    // ── EtherType values — mirrors EtherType namespace ────────────────────────
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_ARP  = 0x0806;

    // ── TCP flag constants — mirrors TCPFlags namespace ───────────────────────
    public static final int TCP_FIN = 0x01;
    public static final int TCP_SYN = 0x02;
    public static final int TCP_RST = 0x04;
    public static final int TCP_PSH = 0x08;
    public static final int TCP_ACK = 0x10;
    public static final int TCP_URG = 0x20;

    // Private constructor — static utility class
    private PacketParser() {}

    /**
     * Parses a raw PCAP packet into a {@link ParsedPacket}.
     * Returns {@code null} if the packet is malformed or too short.
     * Mirrors PacketParser::parse() in packet_parser.cpp.
     */
    public static ParsedPacket parse(RawPacket raw) {
        if (raw == null || raw.data == null || raw.data.length == 0) return null;

        ParsedPacket p = new ParsedPacket();
        p.tsSec   = raw.tsSec;
        p.tsUsec  = raw.tsUsec;
        p.rawData = raw.data;

        ByteBuffer buf = ByteBuffer.wrap(raw.data).order(ByteOrder.BIG_ENDIAN);

        // ── Ethernet header (14 bytes) ────────────────────────────────────────
        if (!parseEthernet(buf, p)) return null;

        // ── IP layer ──────────────────────────────────────────────────────────
        if (p.etherType == ETHERTYPE_IPV4) {
            if (!parseIPv4(buf, p)) return null;

            // ── Transport layer ───────────────────────────────────────────────
            if      (p.protocol == PROTO_TCP) parseTCP(buf, p);
            else if (p.protocol == PROTO_UDP) parseUDP(buf, p);
        }

        // ── Payload ───────────────────────────────────────────────────────────
        int remaining = buf.remaining();
        if (remaining > 0) {
            p.payloadOffset = buf.position();
            p.payloadLength = remaining;
        }

        return p;
    }

    // ── Private parsers ───────────────────────────────────────────────────────

    /** Ethernet header: 6 dst-MAC + 6 src-MAC + 2 EtherType = 14 bytes */
    private static boolean parseEthernet(ByteBuffer buf, ParsedPacket p) {
        if (buf.remaining() < 14) return false;

        byte[] dstMac = new byte[6];
        byte[] srcMac = new byte[6];
        buf.get(dstMac);
        buf.get(srcMac);

        p.dstMac    = macToString(dstMac);
        p.srcMac    = macToString(srcMac);
        p.etherType = Short.toUnsignedInt(buf.getShort());
        return true;
    }

    /** IPv4 header: minimum 20 bytes, may have options. */
    private static boolean parseIPv4(ByteBuffer buf, ParsedPacket p) {
        if (buf.remaining() < 20) return false;

        int startPos = buf.position();
        int versionIhl = Byte.toUnsignedInt(buf.get());
        p.ipVersion = (versionIhl >> 4) & 0x0F;
        if (p.ipVersion != 4) return false;

        int ihl           = versionIhl & 0x0F;
        int ipHeaderBytes = ihl * 4;
        if (ipHeaderBytes < 20 || buf.remaining() < (ipHeaderBytes - 1)) return false;

        buf.get();                                          // TOS — skip
        buf.getShort();                                     // total length — skip
        buf.getShort();                                     // identification — skip
        buf.getShort();                                     // flags+fragment — skip
        p.ttl      = Byte.toUnsignedInt(buf.get());
        p.protocol = Byte.toUnsignedInt(buf.get());
        buf.getShort();                                     // checksum — skip

        byte[] srcIpBytes = new byte[4];
        byte[] dstIpBytes = new byte[4];
        buf.get(srcIpBytes);
        buf.get(dstIpBytes);

        p.srcIp = ipToString(srcIpBytes);
        p.dstIp = ipToString(dstIpBytes);
        p.hasIp = true;

        // Skip any IP options
        int consumed = buf.position() - startPos;
        int skip     = ipHeaderBytes - consumed;
        if (skip > 0) buf.position(buf.position() + skip);

        return true;
    }

    /** TCP header: minimum 20 bytes. */
    private static boolean parseTCP(ByteBuffer buf, ParsedPacket p) {
        if (buf.remaining() < 20) return false;

        p.srcPort   = Short.toUnsignedInt(buf.getShort());
        p.dstPort   = Short.toUnsignedInt(buf.getShort());
        p.seqNumber = Integer.toUnsignedLong(buf.getInt());
        p.ackNumber = Integer.toUnsignedLong(buf.getInt());

        int dataOffset    = (Byte.toUnsignedInt(buf.get()) >> 4) & 0x0F;
        int tcpHeaderBytes = dataOffset * 4;
        p.tcpFlags = Byte.toUnsignedInt(buf.get());

        buf.getShort(); // window
        buf.getShort(); // checksum
        buf.getShort(); // urgent pointer

        // Skip TCP options
        int alreadyRead = 20;
        int skip = tcpHeaderBytes - alreadyRead;
        if (skip > 0 && buf.remaining() >= skip) buf.position(buf.position() + skip);

        p.hasTcp = true;
        return true;
    }

    /** UDP header: always 8 bytes. */
    private static boolean parseUDP(ByteBuffer buf, ParsedPacket p) {
        if (buf.remaining() < 8) return false;

        p.srcPort = Short.toUnsignedInt(buf.getShort());
        p.dstPort = Short.toUnsignedInt(buf.getShort());
        buf.getShort(); // length — skip
        buf.getShort(); // checksum — skip

        p.hasUdp = true;
        return true;
    }

    // ── Static helpers ────────────────────────────────────────────────────────

    /** Formats a 6-byte MAC array as colon-delimited hex. */
    public static String macToString(byte[] mac) {
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", Byte.toUnsignedInt(mac[i])));
        }
        return sb.toString();
    }

    /** Formats a 4-byte IP array (big-endian) as dotted-decimal. */
    public static String ipToString(byte[] ip) {
        return Byte.toUnsignedInt(ip[0]) + "."
             + Byte.toUnsignedInt(ip[1]) + "."
             + Byte.toUnsignedInt(ip[2]) + "."
             + Byte.toUnsignedInt(ip[3]);
    }

    /** Returns a human-readable protocol name. */
    public static String protocolToString(int protocol) {
        return switch (protocol) {
            case PROTO_ICMP -> "ICMP";
            case PROTO_TCP  -> "TCP";
            case PROTO_UDP  -> "UDP";
            default         -> "Unknown(" + protocol + ")";
        };
    }

    /** Returns a human-readable TCP flags string (e.g. "SYN ACK"). */
    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & TCP_SYN) != 0) sb.append("SYN ");
        if ((flags & TCP_ACK) != 0) sb.append("ACK ");
        if ((flags & TCP_FIN) != 0) sb.append("FIN ");
        if ((flags & TCP_RST) != 0) sb.append("RST ");
        if ((flags & TCP_PSH) != 0) sb.append("PSH ");
        if ((flags & TCP_URG) != 0) sb.append("URG ");
        String s = sb.toString().trim();
        return s.isEmpty() ? "none" : s;
    }
}
