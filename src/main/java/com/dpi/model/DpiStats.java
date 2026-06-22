package com.dpi.model;

import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

public class DpiStats {

    private final AtomicLong totalPackets     = new AtomicLong(0);
    private final AtomicLong totalBytes       = new AtomicLong(0);
    private final AtomicLong forwardedPackets = new AtomicLong(0);
    private final AtomicLong droppedPackets   = new AtomicLong(0);
    private final AtomicLong tcpPackets       = new AtomicLong(0);
    private final AtomicLong udpPackets       = new AtomicLong(0);
    private final AtomicLong otherPackets     = new AtomicLong(0);
    private final AtomicLong activeConnections = new AtomicLong(0);

    private final AtomicLong[] appCounts = new AtomicLong[AppType.values().length];

    public DpiStats() {
        for (int i = 0; i < appCounts.length; i++) {
            appCounts[i] = new AtomicLong(0);
        }
    }

    public void recordPacket(ParsedPacket packet, PacketAction action) {
        totalPackets.incrementAndGet();
        totalBytes.addAndGet(packet.getPayloadLength());

        if (action == PacketAction.FORWARD || action == PacketAction.LOG_ONLY) {
            forwardedPackets.incrementAndGet();
        } else if (action == PacketAction.DROP) {
            droppedPackets.incrementAndGet();
        }

        if (packet.isHasTcp()) {
            tcpPackets.incrementAndGet();
        } else if (packet.isHasUdp()) {
            udpPackets.incrementAndGet();
        } else {
            otherPackets.incrementAndGet();
        }

        appCounts[packet.getAppType().ordinal()].incrementAndGet();
    }

    public void incrementActiveConnections() { activeConnections.incrementAndGet(); }
    public void decrementActiveConnections() { activeConnections.decrementAndGet(); }

    public long getAppCount(AppType type) {
        return appCounts[type.ordinal()].get();
    }

    public Snapshot snapshot() {
        Map<AppType, Long> appDist = new java.util.LinkedHashMap<>();
        for (AppType t : AppType.values()) {
            long c = appCounts[t.ordinal()].get();
            if (c > 0) appDist.put(t, c);
        }
        return new Snapshot(
                totalPackets.get(), totalBytes.get(),
                forwardedPackets.get(), droppedPackets.get(),
                tcpPackets.get(), udpPackets.get(), otherPackets.get(),
                activeConnections.get(), appDist
        );
    }

    public record Snapshot(
            long totalPackets,
            long totalBytes,
            long forwardedPackets,
            long droppedPackets,
            long tcpPackets,
            long udpPackets,
            long otherPackets,
            long activeConnections,
            Map<AppType, Long> appDistribution
    ) {}

    public long getTotalPackets()      { return totalPackets.get(); }
    public long getTotalBytes()        { return totalBytes.get(); }
    public long getForwardedPackets()  { return forwardedPackets.get(); }
    public long getDroppedPackets()    { return droppedPackets.get(); }
    public long getTcpPackets()        { return tcpPackets.get(); }
    public long getUdpPackets()        { return udpPackets.get(); }
    public long getOtherPackets()      { return otherPackets.get(); }
    public long getActiveConnections() { return activeConnections.get(); }
}
