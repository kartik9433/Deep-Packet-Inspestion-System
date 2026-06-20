package com.dpi.model;

import lombok.*;
import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor
public class ParsedPacket {

    // Timestamp
    private Instant timestamp;

    // Ethernet layer
    private String srcMac;
    private String dstMac;
    private int etherType;

    // IP layer
    private boolean hasIp;
    private int ipVersion;
    private String srcIp;
    private String dstIp;
    private int protocol;   // 6=TCP, 17=UDP, 1=ICMP
    private int ttl;

    // Transport layer
    private boolean hasTcp;
    private boolean hasUdp;
    private int srcPort;
    private int dstPort;

    // TCP-specific
    private int tcpFlags;
    private long seqNumber;
    private long ackNumber;

    // Payload
    private int payloadLength;
    private byte[] payloadPreview;  // First 32 bytes

    // Classification result (set after DPI)
    private AppType appType = AppType.UNKNOWN;
    private String sni;
    private PacketAction action = PacketAction.FORWARD;

    // Custom helpers — kept manually (logic, not boilerplate)
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