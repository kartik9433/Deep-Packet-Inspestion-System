package com.dpi.service;

import com.dpi.model.ParsedPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;

@Service
public class PacketParserService {

    private static final Logger log = LoggerFactory.getLogger(PacketParserService.class);


    private static final int ETHERTYPE_IPV4 = 0x0800;
    private static final int ETHERTYPE_IPV6 = 0x86DD;
    private static final int ETHERTYPE_ARP  = 0x0806;


    private static final int PROTO_ICMP = 1;
    private static final int PROTO_TCP  = 6;
    private static final int PROTO_UDP  = 17;

    public static final int TCP_FIN = 0x01;
    public static final int TCP_SYN = 0x02;
    public static final int TCP_RST = 0x04;
    public static final int TCP_PSH = 0x08;
    public static final int TCP_ACK = 0x10;
    public static final int TCP_URG = 0x20;

    private static final int ETHERNET_HEADER_LEN = 14;
    private static final int IPV4_MIN_HEADER_LEN = 20;
    private static final int TCP_MIN_HEADER_LEN  = 20;
    private static final int UDP_HEADER_LEN      = 8;


    public ParsedPacket parse(byte[] rawData, long timestampSec, long timestampUsec) {
        if (rawData == null || rawData.length < ETHERNET_HEADER_LEN) {
            return null;
        }

        ParsedPacket pkt = new ParsedPacket();
        pkt.setTimestamp(Instant.ofEpochSecond(timestampSec, timestampUsec * 1000));

        ByteBuffer buf = ByteBuffer.wrap(rawData).order(ByteOrder.BIG_ENDIAN);
        int offset = 0;


        offset = parseEthernet(buf, pkt, offset);
        if (offset < 0) return null;


        if (pkt.getEtherType() == ETHERTYPE_IPV4) {
            offset = parseIPv4(buf, pkt, offset);
            if (offset < 0) return null;

            if (pkt.getProtocol() == PROTO_TCP) {
                parseTcp(buf, pkt, offset);
            } else if (pkt.getProtocol() == PROTO_UDP) {
                parseUdp(buf, pkt, offset);
            }
        }

        return pkt;
    }


    private int parseEthernet(ByteBuffer buf, ParsedPacket pkt, int offset) {
        if (buf.capacity() < offset + ETHERNET_HEADER_LEN) return -1;

        byte[] dstMac = new byte[6];
        byte[] srcMac = new byte[6];
        buf.position(offset);
        buf.get(dstMac);
        buf.get(srcMac);
        int etherType = buf.getShort() & 0xFFFF;

        pkt.setDstMac(macToString(dstMac));
        pkt.setSrcMac(macToString(srcMac));
        pkt.setEtherType(etherType);

        return offset + ETHERNET_HEADER_LEN;
    }

    private int parseIPv4(ByteBuffer buf, ParsedPacket pkt, int offset) {
        if (buf.capacity() < offset + IPV4_MIN_HEADER_LEN) return -1;

        buf.position(offset);
        int versionIhl = buf.get() & 0xFF;
        int version = (versionIhl >> 4) & 0xF;
        int ihl = (versionIhl & 0xF) * 4;  // header length in bytes

        buf.get(); // TOS
        buf.getShort(); // total length
        buf.getShort(); // identification
        buf.getShort(); // flags + fragment offset
        int ttl = buf.get() & 0xFF;
        int protocol = buf.get() & 0xFF;
        buf.getShort(); // checksum
        int srcIpRaw = buf.getInt();
        int dstIpRaw = buf.getInt();

        pkt.setHasIp(true);
        pkt.setIpVersion(version);
        pkt.setTtl(ttl);
        pkt.setProtocol(protocol);
        pkt.setSrcIp(ipToString(srcIpRaw));
        pkt.setDstIp(ipToString(dstIpRaw));

        return offset + ihl;
    }

    private void parseTcp(ByteBuffer buf, ParsedPacket pkt, int offset) {
        if (buf.capacity() < offset + TCP_MIN_HEADER_LEN) return;

        buf.position(offset);
        int srcPort = buf.getShort() & 0xFFFF;
        int dstPort = buf.getShort() & 0xFFFF;
        long seqNum = buf.getInt() & 0xFFFFFFFFL;
        long ackNum = buf.getInt() & 0xFFFFFFFFL;
        int dataOffset = ((buf.get() & 0xFF) >> 4) * 4;
        int flags = buf.get() & 0xFF;
        buf.getShort(); // window
        buf.getShort(); // checksum
        buf.getShort(); // urgent pointer

        pkt.setHasTcp(true);
        pkt.setSrcPort(srcPort);
        pkt.setDstPort(dstPort);
        pkt.setSeqNumber(seqNum);
        pkt.setAckNumber(ackNum);
        pkt.setTcpFlags(flags);

        int payloadOffset = offset + dataOffset;
        int payloadLength = Math.max(0, buf.capacity() - payloadOffset);
        pkt.setPayloadLength(payloadLength);

        if (payloadLength > 0 && payloadOffset < buf.capacity()) {
            int previewLen = Math.min(payloadLength, 32);
            byte[] preview = new byte[previewLen];
            buf.position(payloadOffset);
            buf.get(preview, 0, previewLen);
            pkt.setPayloadPreview(preview);
        }
    }

    private void parseUdp(ByteBuffer buf, ParsedPacket pkt, int offset) {
        if (buf.capacity() < offset + UDP_HEADER_LEN) return;

        buf.position(offset);
        int srcPort = buf.getShort() & 0xFFFF;
        int dstPort = buf.getShort() & 0xFFFF;
        int length  = buf.getShort() & 0xFFFF;
        buf.getShort(); // checksum

        pkt.setHasUdp(true);
        pkt.setSrcPort(srcPort);
        pkt.setDstPort(dstPort);
        pkt.setPayloadLength(Math.max(0, length - UDP_HEADER_LEN));
    }


    public static String macToString(byte[] mac) {
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
                mac[0] & 0xFF, mac[1] & 0xFF, mac[2] & 0xFF,
                mac[3] & 0xFF, mac[4] & 0xFF, mac[5] & 0xFF);
    }

    public static String ipToString(int ip) {
        return String.format("%d.%d.%d.%d",
                (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                (ip >>  8) & 0xFF,  ip        & 0xFF);
    }

    public static String etherTypeToString(int etherType) {
        return switch (etherType) {
            case ETHERTYPE_IPV4 -> "IPv4";
            case ETHERTYPE_IPV6 -> "IPv6";
            case ETHERTYPE_ARP  -> "ARP";
            default -> String.format("0x%04X", etherType);
        };
    }
}
