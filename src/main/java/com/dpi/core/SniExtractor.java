package com.dpi.core;

import java.nio.charset.StandardCharsets;

/**
 * Extracts the TLS Server Name Indication (SNI) from a TLS ClientHello payload.
 * Mirrors the logic in src/sni_extractor.cpp.
 *
 * No external libraries — pure byte-level parsing of the TLS record and
 * handshake structures, same approach as the C++ implementation.
 */
public class SniExtractor {

    private SniExtractor() {}

    // TLS record content type
    private static final int TLS_HANDSHAKE          = 22;
    private static final int TLS_CLIENT_HELLO       = 1;
    private static final int EXTENSION_SNI           = 0;
    private static final int SNI_TYPE_HOST_NAME      = 0;

    /**
     * Attempts to extract the SNI hostname from a raw TLS payload.
     *
     * @param payload raw bytes starting at the TLS record layer
     * @param offset  starting offset within payload
     * @param length  number of bytes available
     * @return the SNI hostname, or {@code null} if not found / not a ClientHello
     */
    public static String extract(byte[] payload, int offset, int length) {
        if (payload == null || length < 5) return null;

        int pos = offset;
        int end = offset + length;

        // TLS Record header: content_type(1) + version(2) + length(2)
        if (end - pos < 5) return null;
        int contentType = Byte.toUnsignedInt(payload[pos]);
        if (contentType != TLS_HANDSHAKE) return null;
        pos += 3; // skip content_type + version
        int recordLen = readUint16(payload, pos); pos += 2;

        if (end - pos < recordLen) return null;

        // Handshake header: type(1) + length(3)
        if (end - pos < 4) return null;
        int hsType = Byte.toUnsignedInt(payload[pos]); pos++;
        if (hsType != TLS_CLIENT_HELLO) return null;
        int hsLen = readUint24(payload, pos); pos += 3;
        if (end - pos < hsLen) return null;

        // ClientHello body:
        //   client_version(2) + random(32) + session_id_len(1) + session_id(var)
        //   + cipher_suites_len(2) + cipher_suites(var)
        //   + compression_methods_len(1) + compression_methods(var)
        //   + extensions_len(2) + extensions(var)
        if (end - pos < 35) return null;
        pos += 2;  // client_version
        pos += 32; // random

        // session_id
        int sessionIdLen = Byte.toUnsignedInt(payload[pos]); pos++;
        pos += sessionIdLen;
        if (end - pos < 2) return null;

        // cipher_suites
        int cipherLen = readUint16(payload, pos); pos += 2;
        pos += cipherLen;
        if (end - pos < 1) return null;

        // compression_methods
        int compLen = Byte.toUnsignedInt(payload[pos]); pos++;
        pos += compLen;
        if (end - pos < 2) return null;

        // extensions
        int extTotalLen = readUint16(payload, pos); pos += 2;
        int extEnd = pos + extTotalLen;
        if (extEnd > end) extEnd = end;

        while (pos + 4 <= extEnd) {
            int extType = readUint16(payload, pos); pos += 2;
            int extLen  = readUint16(payload, pos); pos += 2;
            int nextExt = pos + extLen;

            if (extType == EXTENSION_SNI && extLen >= 5) {
                // SNI extension: list_len(2) + type(1) + name_len(2) + name(var)
                int listLen = readUint16(payload, pos); pos += 2;
                if (pos + 3 <= nextExt) {
                    int nameType = Byte.toUnsignedInt(payload[pos]); pos++;
                    if (nameType == SNI_TYPE_HOST_NAME) {
                        int nameLen = readUint16(payload, pos); pos += 2;
                        if (pos + nameLen <= nextExt) {
                            return new String(payload, pos, nameLen, StandardCharsets.US_ASCII);
                        }
                    }
                }
                return null; // found SNI extension but couldn't parse it
            }

            pos = nextExt; // advance to next extension
        }

        return null; // no SNI extension found
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static int readUint16(byte[] b, int offset) {
        return ((Byte.toUnsignedInt(b[offset]) << 8) | Byte.toUnsignedInt(b[offset + 1]));
    }

    private static int readUint24(byte[] b, int offset) {
        return (Byte.toUnsignedInt(b[offset]) << 16)
             | (Byte.toUnsignedInt(b[offset + 1]) << 8)
             |  Byte.toUnsignedInt(b[offset + 2]);
    }
}
