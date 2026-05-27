package com.dpi.engine;

import com.dpi.model.PacketJob;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Writes forwarded packets to a PCAP output file.
 * Mirrors the output-writing logic in DPIEngine::writeOutputPacket()
 * and DPIEngine::writeOutputHeader() in dpi_engine.cpp.
 *
 * Writes a standard legacy pcap file (magic 0xa1b2c3d4, little-endian).
 */
public class PcapWriter implements Closeable {

    private static final Logger log = LoggerFactory.getLogger(PcapWriter.class);

    private static final int PCAP_MAGIC   = 0xa1b2c3d4;
    private static final int VERSION_MAJ  = 2;
    private static final int VERSION_MIN  = 4;
    private static final int SNAPLEN      = 65535;
    private static final int LINK_TYPE    = 1; // Ethernet

    private BufferedOutputStream out;

    public void open(Path path) throws IOException {
        out = new BufferedOutputStream(Files.newOutputStream(path));
        writeGlobalHeader();
        log.info("Opened output PCAP: {}", path);
    }

    /** Writes a PCAP global header (24 bytes, little-endian). */
    private void writeGlobalHeader() throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(PCAP_MAGIC);
        buf.putShort((short) VERSION_MAJ);
        buf.putShort((short) VERSION_MIN);
        buf.putInt(0);          // thiszone
        buf.putInt(0);          // sigfigs
        buf.putInt(SNAPLEN);
        buf.putInt(LINK_TYPE);
        out.write(buf.array());
    }

    /**
     * Writes a single packet to the output file.
     * Mirrors DPIEngine::writeOutputPacket().
     */
    public synchronized void writePacket(PacketJob job) throws IOException {
        if (out == null) throw new IllegalStateException("PcapWriter is not open");
        if (job.data == null) return;

        ByteBuffer hdr = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        hdr.putInt((int) job.tsSec);
        hdr.putInt((int) job.tsUsec);
        hdr.putInt(job.data.length);
        hdr.putInt(job.data.length);
        out.write(hdr.array());
        out.write(job.data);
    }

    public void flush() throws IOException {
        if (out != null) out.flush();
    }

    @Override
    public void close() throws IOException {
        if (out != null) {
            out.flush();
            out.close();
            out = null;
        }
    }
}
