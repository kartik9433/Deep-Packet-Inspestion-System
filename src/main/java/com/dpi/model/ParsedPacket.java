package com.dpi.model;

import lombok.*;
import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor
public class ParsedPacket {

    private Instant timestamp;

    private String srcMac;
    private String dstMac;
    private int etherType;

    private boolean hasIp;
    private int ipVersion;
    private String srcIp;
    private String dstIp;
    private int protocol;
    private int ttl;

    private boolean hasTcp;
    private boolean hasUdp;
    private int srcPort;
    private int dstPort;

    private int tcpFlags;
    private long seqNumber;
    private long ackNumber;

    private int payloadLength;
    private byte[] payloadPreview;

    private AppType appType = AppType.UNKNOWN;
    private String sni;
    private PacketAction action = PacketAction.FORWARD;

    public FiveTuple toFiveTuple() {
        return new FiveTuple(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    public String getTcpFlagsString() {
        if (!hasTcp) return "";
        StringBuilder sb = new StringBuilder();
        if ((tcpFlags & 0x02) != 0) sb.append("SYN ");
        if ((tcpFlags & 0x10) != 0) sb.append("ACK ");
        if ((tcpFlags & 0x01) != 0) sb.append("FIN ");
        if ((tcpFlags & 0x04) != 0) sb.append("RST ");
        if ((tcpFlags & 0x08) != 0) sb.append("PSH ");
        if ((tcpFlags & 0x20) != 0) sb.append("URG ");
        return sb.toString().trim();
    }

    public String getProtocolName() {
        return switch (protocol) {
            case 6  -> "TCP";
            case 17 -> "UDP";
            case 1  -> "ICMP";
            default -> "OTHER";
        };
    }
}