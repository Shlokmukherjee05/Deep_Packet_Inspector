package com.dpi.core;

import com.dpi.model.RawPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Reads a legacy libpcap (.pcap) file packet by packet.
 * Mirrors PacketAnalyzer::PcapReader in pcap_reader.h / pcap_reader.cpp.
 *
 * Handles both native (little-endian) and byte-swapped (big-endian) PCAP files
 * via the magic-number check, exactly as the C++ version does.
 */
public class PcapReader implements Closeable {

    private static final Logger log = LoggerFactory.getLogger(PcapReader.class);

    // Magic numbers — mirrors C++ PCAP_MAGIC_NATIVE / PCAP_MAGIC_SWAPPED
    private static final int MAGIC_NATIVE  = 0xa1b2c3d4;
    private static final int MAGIC_SWAPPED = 0xd4c3b2a1;

    // PCAP global-header fields (stored after parsing)
    private int  versionMajor;
    private int  versionMinor;
    private long snaplen;
    private int  network;       // data-link type (1 = Ethernet)
    private boolean needsSwap;

    private DataInputStream in;

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Opens a PCAP file and reads its global header.
     * Mirrors PcapReader::open() in pcap_reader.cpp.
     *
     * @param path path to the .pcap file
     * @throws IOException if the file cannot be read or is not a valid PCAP
     */
    public void open(Path path) throws IOException {
        close(); // close any previously opened file

        in = new DataInputStream(new BufferedInputStream(Files.newInputStream(path)));

        // Read global header (24 bytes) — always in file's native byte order first
        // We peek at the magic to determine byte-order, then re-read accordingly.
        byte[] hdrBytes = in.readNBytes(24);
        if (hdrBytes.length < 24) {
            throw new IOException("File too short to contain a PCAP global header");
        }

        // Check magic in little-endian first (most common)
        int magicLE = ByteBuffer.wrap(hdrBytes).order(ByteOrder.LITTLE_ENDIAN).getInt(0);
        int magicBE = ByteBuffer.wrap(hdrBytes).order(ByteOrder.BIG_ENDIAN).getInt(0);

        ByteOrder order;
        if (magicLE == MAGIC_NATIVE) {
            needsSwap = false; // file is little-endian, same as x86 host
            order = ByteOrder.LITTLE_ENDIAN;
        } else if (magicBE == MAGIC_NATIVE || magicLE == MAGIC_SWAPPED) {
            needsSwap = true;
            order = ByteOrder.BIG_ENDIAN;
        } else {
            throw new IOException(
                String.format("Invalid PCAP magic number: 0x%08X", magicLE));
        }

        ByteBuffer hdr = ByteBuffer.wrap(hdrBytes).order(order);
        hdr.getInt();                          // skip magic (already read)
        versionMajor = Short.toUnsignedInt(hdr.getShort());
        versionMinor = Short.toUnsignedInt(hdr.getShort());
        hdr.getInt();                          // thiszone (GMT offset) — ignored
        hdr.getInt();                          // sigfigs — ignored
        snaplen      = Integer.toUnsignedLong(hdr.getInt());
        network      = hdr.getInt();

        log.info("Opened PCAP: {}", path);
        log.info("  Version  : {}.{}", versionMajor, versionMinor);
        log.info("  Snaplen  : {} bytes", snaplen);
        log.info("  Link type: {}{}", network, network == 1 ? " (Ethernet)" : "");
    }

    /**
     * Reads the next packet from the file.
     * Mirrors PcapReader::readNextPacket() in pcap_reader.cpp.
     *
     * @return the next {@link RawPacket}, or {@code null} at EOF
     * @throws IOException on a read error (not EOF)
     */
    public RawPacket readNextPacket() throws IOException {
        if (in == null) throw new IllegalStateException("PcapReader is not open");

        // Try to read the 16-byte packet header
        byte[] phdrBytes;
        try {
            phdrBytes = in.readNBytes(16);
        } catch (EOFException e) {
            return null;
        }
        if (phdrBytes.length == 0) return null;   // clean EOF
        if (phdrBytes.length < 16) throw new IOException("Truncated packet header");

        ByteOrder order = needsSwap ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
        ByteBuffer phdr = ByteBuffer.wrap(phdrBytes).order(order);

        RawPacket pkt = new RawPacket();
        pkt.tsSec   = Integer.toUnsignedLong(phdr.getInt());
        pkt.tsUsec  = Integer.toUnsignedLong(phdr.getInt());
        pkt.inclLen = phdr.getInt();
        pkt.origLen = phdr.getInt();

        // Sanity check — mirrors the C++ guard
        if (Integer.toUnsignedLong(pkt.inclLen) > snaplen || pkt.inclLen < 0 || pkt.inclLen > 65535) {
            throw new IOException("Invalid packet length: " + Integer.toUnsignedLong(pkt.inclLen));
        }

        pkt.data = in.readNBytes(pkt.inclLen);
        if (pkt.data.length < pkt.inclLen) {
            throw new IOException("Truncated packet data (expected " + pkt.inclLen + " bytes)");
        }

        return pkt;
    }

    @Override
    public void close() throws IOException {
        if (in != null) {
            in.close();
            in = null;
        }
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    public int  getVersionMajor() { return versionMajor; }
    public int  getVersionMinor() { return versionMinor; }
    public long getSnaplen()      { return snaplen; }
    public int  getNetwork()      { return network; }
    public boolean isOpen()       { return in != null; }
}
