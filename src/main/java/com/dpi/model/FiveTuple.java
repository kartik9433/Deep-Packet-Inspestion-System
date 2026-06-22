package com.dpi.model;

import java.util.Objects;

public class FiveTuple {

    private final String srcIp;
    private final String dstIp;
    private final int srcPort;
    private final int dstPort;
    private final int protocol;  // TCP=6, UDP=17, ICMP=1

    public FiveTuple(String srcIp, String dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    public String getSrcIp() { return srcIp; }
    public String getDstIp() { return dstIp; }
    public int getSrcPort() { return srcPort; }
    public int getDstPort() { return dstPort; }
    public int getProtocol() { return protocol; }

    public String getProtocolName() {
        return switch (protocol) {
            case 6  -> "TCP";
            case 17 -> "UDP";
            case 1  -> "ICMP";
            default -> "UNKNOWN(" + protocol + ")";
        };
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple t)) return false;
        return srcPort == t.srcPort && dstPort == t.dstPort && protocol == t.protocol
                && Objects.equals(srcIp, t.srcIp) && Objects.equals(dstIp, t.dstIp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    @Override
    public String toString() {
        return String.format("%s:%d -> %s:%d [%s]", srcIp, srcPort, dstIp, dstPort, getProtocolName());
    }
}
