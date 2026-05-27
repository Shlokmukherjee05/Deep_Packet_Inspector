package com.dpi.model;

import java.util.Objects;

/**
 * Five-tuple that uniquely identifies a network flow.
 * Mirrors DPI::FiveTuple in types.h / types.cpp.
 *
 * IPs are stored as plain int (Java has no unsigned types) — treat bits as
 * unsigned when formatting.  Byte-order matches the C++ version: network
 * (big-endian) order as read from the PCAP.
 */
public final class FiveTuple {

    public static final int PROTO_TCP  = 6;
    public static final int PROTO_UDP  = 17;
    public static final int PROTO_ICMP = 1;

    /** Source IP in network byte order (stored as int, treated as unsigned) */
    public final int   srcIp;
    /** Destination IP in network byte order */
    public final int   dstIp;
    public final short srcPort;   // unsigned 16-bit, use Short.toUnsignedInt()
    public final short dstPort;
    public final byte  protocol;  // unsigned 8-bit, use Byte.toUnsignedInt()

    public FiveTuple(int srcIp, int dstIp, short srcPort, short dstPort, byte protocol) {
        this.srcIp    = srcIp;
        this.dstIp    = dstIp;
        this.srcPort  = srcPort;
        this.dstPort  = dstPort;
        this.protocol = protocol;
    }

    /** Returns the reverse tuple (for bidirectional flow matching) */
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple t)) return false;
        return srcIp == t.srcIp && dstIp == t.dstIp &&
               srcPort == t.srcPort && dstPort == t.dstPort &&
               protocol == t.protocol;
    }

    @Override
    public int hashCode() {
        // Same mixing as the C++ FiveTupleHash for conceptual parity
        return Objects.hash(Integer.toUnsignedLong(srcIp),
                            Integer.toUnsignedLong(dstIp),
                            Short.toUnsignedInt(srcPort),
                            Short.toUnsignedInt(dstPort),
                            Byte.toUnsignedInt(protocol));
    }

    @Override
    public String toString() {
        String proto = switch (Byte.toUnsignedInt(protocol)) {
            case PROTO_TCP  -> "TCP";
            case PROTO_UDP  -> "UDP";
            case PROTO_ICMP -> "ICMP";
            default         -> "?" + Byte.toUnsignedInt(protocol);
        };
        return ipToString(srcIp) + ":" + Short.toUnsignedInt(srcPort)
             + " -> "
             + ipToString(dstIp) + ":" + Short.toUnsignedInt(dstPort)
             + " (" + proto + ")";
    }

    /** Formats a network-byte-order IP int as a dotted-decimal string. */
    public static String ipToString(int ip) {
        return (ip & 0xFF) + "."
             + ((ip >> 8)  & 0xFF) + "."
             + ((ip >> 16) & 0xFF) + "."
             + ((ip >> 24) & 0xFF);
    }

    /**
     * Parses a dotted-decimal IPv4 string into a network-byte-order int.
     * Mirrors RuleManager::parseIP() from rule_manager.cpp.
     */
    public static int parseIp(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) throw new IllegalArgumentException("Invalid IP: " + ip);
        int result = 0;
        for (int i = 0; i < 4; i++) {
            int octet = Integer.parseInt(parts[i].trim());
            if (octet < 0 || octet > 255) throw new IllegalArgumentException("Invalid octet: " + octet);
            result |= (octet << (i * 8));
        }
        return result;
    }
}
