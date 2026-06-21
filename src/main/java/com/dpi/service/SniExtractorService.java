package com.dpi.service;

import org.springframework.stereotype.Service;

@Service
public class SniExtractorService {

    private static final int TLS_CONTENT_HANDSHAKE = 0x16;
    private static final int TLS_HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int TLS_EXT_SNI = 0x0000;
    private static final int TLS_SNI_TYPE_HOST = 0x00;

    public String extract(byte[] payload) {
        if (payload == null || payload.length < 5) return null;

        if ((payload[0] & 0xFF) != TLS_CONTENT_HANDSHAKE) return null;

        if (payload.length < 5) return null;
        int recordLen = ((payload[3] & 0xFF) << 8) | (payload[4] & 0xFF);
        if (payload.length < 5 + recordLen) return null;

        int offset = 5;

        // Handshake type
        if ((payload[offset] & 0xFF) != TLS_HANDSHAKE_CLIENT_HELLO) return null;
        offset++;

        if (offset + 3 > payload.length) return null;
        offset += 3;

        offset += 2;

        offset += 32;

        if (offset >= payload.length) return null;

        int sessionIdLen = payload[offset] & 0xFF;
        offset += 1 + sessionIdLen;
        if (offset + 2 > payload.length) return null;

        int cipherSuitesLen = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
        offset += 2 + cipherSuitesLen;
        if (offset + 1 > payload.length) return null;


        int compressionLen = payload[offset] & 0xFF;
        offset += 1 + compressionLen;
        if (offset + 2 > payload.length) return null;


        int extensionsLen = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
        offset += 2;
        int extensionsEnd = offset + extensionsLen;

        while (offset + 4 <= extensionsEnd && offset + 4 <= payload.length) {
            int extType = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
            int extLen  = ((payload[offset + 2] & 0xFF) << 8) | (payload[offset + 3] & 0xFF);
            offset += 4;

            if (extType == TLS_EXT_SNI) {

                if (offset + 2 > payload.length) return null;
                int sniListLen = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
                offset += 2;

                if (offset + 3 > payload.length) return null;
                int sniType = payload[offset] & 0xFF;
                int sniLen  = ((payload[offset + 1] & 0xFF) << 8) | (payload[offset + 2] & 0xFF);
                offset += 3;

                if (sniType == TLS_SNI_TYPE_HOST && offset + sniLen <= payload.length) {
                    return new String(payload, offset, sniLen);
                }
                return null;
            }

            offset += extLen;
        }

        return null;
    }
}
