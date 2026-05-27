package com.dpi;

import com.dpi.core.PacketParser;
import com.dpi.core.PcapReader;
import com.dpi.engine.DpiEngine;
import com.dpi.model.ParsedPacket;
import com.dpi.model.RawPacket;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Entry point for the Deep Packet Inspector.
 *
 * Two operating modes (mirrors the C++ main.cpp + main_dpi.cpp):
 *
 *   1. Simple mode (default):   reads a PCAP and prints each packet to stdout.
 *   2. DPI mode   (--dpi flag): full multi-threaded DPI pipeline with rule-based
 *                               blocking and PCAP output.
 *
 * Usage:
 *   java -jar deep-packet-inspector.jar <pcap_file> [max_packets]
 *   java -jar deep-packet-inspector.jar --dpi <input.pcap> <output.pcap> [rules_file]
 */
public class Main {

    private static final DateTimeFormatter TS_FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    public static void main(String[] args) throws IOException {
        System.out.println("====================================");
        System.out.println("     Deep Packet Inspector v1.0");
        System.out.println("     (Java port of C++ version)");
        System.out.println("====================================\n");

        if (args.length == 0) {
            printUsage();
            System.exit(1);
        }

        if (args[0].equals("--dpi")) {
            runDpiMode(args);
        } else {
            runSimpleMode(args);
        }
    }

    // ── Simple mode ───────────────────────────────────────────────────────────

    /**
     * Reads a PCAP and prints each packet.
     * Mirrors the C++ main.cpp behaviour.
     */
    private static void runSimpleMode(String[] args) throws IOException {
        String pcapFile    = args[0];
        int    maxPackets  = args.length >= 2 ? Integer.parseInt(args[1]) : -1;

        PcapReader reader = new PcapReader();
        reader.open(Path.of(pcapFile));

        System.out.println("\n--- Reading packets ---");

        RawPacket raw;
        int packetCount  = 0;
        int parseErrors  = 0;

        while ((raw = reader.readNextPacket()) != null) {
            packetCount++;
            ParsedPacket p = PacketParser.parse(raw);
            if (p != null) {
                printPacketSummary(p, packetCount);
            } else {
                System.err.println("Warning: Failed to parse packet #" + packetCount);
                parseErrors++;
            }
            if (maxPackets > 0 && packetCount >= maxPackets) {
                System.out.println("\n(Stopped after " + maxPackets + " packets)");
                break;
            }
        }

        reader.close();

        System.out.println("\n====================================");
        System.out.println("Summary:");
        System.out.println("  Total packets read : " + packetCount);
        System.out.println("  Parse errors       : " + parseErrors);
        System.out.println("====================================");
    }

    /** Mirrors printPacketSummary() from main.cpp */
    private static void printPacketSummary(ParsedPacket p, int num) {
        String ts = TS_FMT.format(Instant.ofEpochSecond(p.tsSec))
                  + String.format(".%06d", p.tsUsec);

        System.out.println("\n========== Packet #" + num + " ==========");
        System.out.println("Time: " + ts);

        System.out.println("\n[Ethernet]");
        System.out.println("  Source MAC:      " + p.srcMac);
        System.out.println("  Destination MAC: " + p.dstMac);
        String etLabel = switch (p.etherType) {
            case ParsedPacket.ETHERTYPE_IPV4 -> " (IPv4)";
            case ParsedPacket.ETHERTYPE_IPV6 -> " (IPv6)";
            case ParsedPacket.ETHERTYPE_ARP  -> " (ARP)";
            default -> "";
        };
        System.out.printf("  EtherType:       0x%04X%s%n", p.etherType, etLabel);

        if (p.hasIp) {
            System.out.println("\n[IPv" + p.ipVersion + "]");
            System.out.println("  Source IP:      " + p.srcIp);
            System.out.println("  Destination IP: " + p.dstIp);
            System.out.println("  Protocol:       " + PacketParser.protocolToString(p.protocol));
            System.out.println("  TTL:            " + p.ttl);
        }

        if (p.hasTcp) {
            System.out.println("\n[TCP]");
            System.out.println("  Source Port:      " + p.srcPort);
            System.out.println("  Destination Port: " + p.dstPort);
            System.out.println("  Sequence Number:  " + p.seqNumber);
            System.out.println("  Ack Number:       " + p.ackNumber);
            System.out.println("  Flags:            " + PacketParser.tcpFlagsToString(p.tcpFlags));
        }

        if (p.hasUdp) {
            System.out.println("\n[UDP]");
            System.out.println("  Source Port:      " + p.srcPort);
            System.out.println("  Destination Port: " + p.dstPort);
        }

        if (p.payloadLength > 0) {
            System.out.println("\n[Payload]");
            System.out.println("  Length: " + p.payloadLength + " bytes");
            // Print first 32 bytes as hex — mirrors the C++ preview
            int preview = Math.min(p.payloadLength, 32);
            StringBuilder hex = new StringBuilder("  Preview: ");
            for (int i = 0; i < preview; i++) {
                hex.append(String.format("%02x ", p.rawData[p.payloadOffset + i] & 0xFF));
            }
            if (p.payloadLength > 32) hex.append("...");
            System.out.println(hex);
        }
    }

    // ── DPI mode ──────────────────────────────────────────────────────────────

    /**
     * Full pipeline mode.
     * Mirrors the C++ main_dpi.cpp / DPIEngine usage.
     *
     * Arguments: --dpi <input.pcap> <output.pcap> [rules_file]
     */
    private static void runDpiMode(String[] args) throws IOException {
        if (args.length < 3) {
            System.err.println("DPI mode requires: --dpi <input.pcap> <output.pcap> [rules_file]");
            System.exit(1);
        }

        String inputFile  = args[1];
        String outputFile = args[2];
        String rulesFile  = args.length >= 4 ? args[3] : null;

        var config = new DpiEngine.Config(2, 2, 10_000, rulesFile, true);
        DpiEngine engine = new DpiEngine(config);

        if (!engine.initialize()) {
            System.err.println("Failed to initialise DPI engine");
            System.exit(1);
        }

        boolean ok = engine.processFile(Path.of(inputFile), Path.of(outputFile));
        System.out.println(engine.generateReport());

        System.exit(ok ? 0 : 1);
    }

    // ── Usage ─────────────────────────────────────────────────────────────────

    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  Simple mode : java -jar dpi.jar <pcap_file> [max_packets]");
        System.out.println("  DPI mode    : java -jar dpi.jar --dpi <input.pcap> <output.pcap> [rules_file]");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java -jar dpi.jar capture.pcap");
        System.out.println("  java -jar dpi.jar capture.pcap 10");
        System.out.println("  java -jar dpi.jar --dpi traffic.pcap out.pcap rules.txt");
    }
}
