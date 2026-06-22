package com.dpi.service;

import com.dpi.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class DpiEngineService {

    private static final Logger log = LoggerFactory.getLogger(DpiEngineService.class);

    private static final int PCAP_MAGIC_LE       = (int) 0xD4C3B2A1L;
    private static final int PCAP_MAGIC_BE       = (int) 0xA1B2C3D4L;
    private static final int PCAP_MAGIC_NS_LE    = (int) 0x4D3CB2A1L;
    private static final int PCAP_MAGIC_NS_BE    = (int) 0xA1B23C4DL;
    private static final int PCAP_GLOBAL_HDR_LEN = 24;
    private static final int PCAP_PKT_HDR_LEN    = 16;

    private final PacketParserService      parserService;
    private final SniExtractorService      sniExtractor;
    private final RuleManagerService       ruleManager;
    private final ConnectionTrackerService connTracker;
    private final DpiStats                 stats;

    private final AtomicBoolean running  = new AtomicBoolean(false);
    private final AtomicLong    packetId = new AtomicLong(0);

    private final ExecutorService threadPool;

    public DpiEngineService(PacketParserService parserService,
                            SniExtractorService sniExtractor,
                            RuleManagerService ruleManager,
                            ConnectionTrackerService connTracker,
                            DpiStats stats) {
        this.parserService = parserService;
        this.sniExtractor  = sniExtractor;
        this.ruleManager   = ruleManager;
        this.connTracker   = connTracker;
        this.stats         = stats;
        this.threadPool    = Executors.newFixedThreadPool(4);
    }

    @Async
    public CompletableFuture<ProcessingResult> processFile(String inputPath, String outputPath) {
        if (!running.compareAndSet(false, true)) {
            return CompletableFuture.completedFuture(
                    new ProcessingResult(false, "Engine already processing a file", 0, 0, 0));
        }

        log.info("[DPIEngine] Starting processing: {}", inputPath);

        try (FileInputStream fis = new FileInputStream(inputPath)) {


            byte[] globalHdr = fis.readNBytes(PCAP_GLOBAL_HDR_LEN);
            if (globalHdr.length < PCAP_GLOBAL_HDR_LEN) {
                return result(false, "File too small to be a valid PCAP", 0, 0, 0);
            }

            PcapGlobalHeader header = parsePcapGlobalHeader(globalHdr);
            if (header == null) {
                return result(false, "Invalid PCAP magic number", 0, 0, 0);
            }

            log.info("[DPIEngine] PCAP version={}.{}, linkType={}, snapLen={}, swapBytes={}",
                    header.versionMajor(), header.versionMinor(),
                    header.linkType(), header.snapLen(), header.swapBytes());


            List<ParsedPacket> forwardedPackets = new ArrayList<>();
            long total = 0, forwarded = 0, dropped = 0;

            byte[] pktHdr = new byte[PCAP_PKT_HDR_LEN];
            while (fis.read(pktHdr) == PCAP_PKT_HDR_LEN) {

                PcapPacketHeader ph = parsePcapPacketHeader(pktHdr, header.swapBytes());
                if (ph == null) {
                    log.warn("[DPIEngine] Null packet header — stopping.");
                    break;
                }

                if (ph.inclLen() <= 0 || ph.inclLen() > 65535) {
                    log.warn("[DPIEngine] Suspicious inclLen={} — skipping packet", ph.inclLen());
                    continue;
                }

                byte[] rawData = fis.readNBytes(ph.inclLen());
                if (rawData.length < ph.inclLen()) {
                    log.warn("[DPIEngine] Short read: expected {} got {} — stopping", ph.inclLen(), rawData.length);
                    break;
                }

                total++;
                long id = packetId.incrementAndGet();

                ParsedPacket parsed = parserService.parse(rawData, ph.tsSec(), ph.tsUsec());
                if (parsed == null) {
                    log.debug("[DPIEngine] parse() returned null for packet #{}", id);
                    continue;
                }

                PacketAction action = classifyAndDecide(parsed);
                parsed.setAction(action);
                stats.recordPacket(parsed, action);

                if (action == PacketAction.FORWARD || action == PacketAction.LOG_ONLY) {
                    forwardedPackets.add(parsed);
                    forwarded++;
                } else {
                    dropped++;
                    log.debug("[DPIEngine] Dropped packet #{}: {} -> {}",
                            id, parsed.getSrcIp(), parsed.getDstIp());
                }
            }

            if (outputPath != null && !outputPath.isBlank()) {
                writePcap(outputPath, forwardedPackets, header);
            }

            String msg = String.format("Processed %d packets: %d forwarded, %d dropped",
                    total, forwarded, dropped);
            log.info("[DPIEngine] {}", msg);
            return result(true, msg, total, forwarded, dropped);

        } catch (IOException e) {
            log.error("[DPIEngine] IO error: {}", e.getMessage(), e);
            return result(false, "IO Error: " + e.getMessage(), 0, 0, 0);
        } finally {
            running.set(false);
        }
    }

    public PacketAction processPacket(byte[] rawData, long tsSec, long tsUsec) {
        ParsedPacket parsed = parserService.parse(rawData, tsSec, tsUsec);
        if (parsed == null) return PacketAction.DROP;

        PacketAction action = classifyAndDecide(parsed);
        stats.recordPacket(parsed, action);
        return action;
    }

    public DpiStats.Snapshot getStats() {
        return stats.snapshot();
    }

    public boolean isRunning() {
        return running.get();
    }

    public String generateReport() {
        DpiStats.Snapshot snap = stats.snapshot();
        StringBuilder sb = new StringBuilder();
        sb.append("=== DPI Engine Report ===\n");
        sb.append(String.format("Total Packets    : %d%n", snap.totalPackets()));
        sb.append(String.format("Total Bytes      : %d%n", snap.totalBytes()));
        sb.append(String.format("Forwarded        : %d%n", snap.forwardedPackets()));
        sb.append(String.format("Dropped          : %d%n", snap.droppedPackets()));
        sb.append(String.format("TCP Packets      : %d%n", snap.tcpPackets()));
        sb.append(String.format("UDP Packets      : %d%n", snap.udpPackets()));
        sb.append(String.format("Active Conns     : %d%n", snap.activeConnections()));
        sb.append("\n=== Application Distribution ===\n");
        snap.appDistribution().forEach((app, count) ->
                sb.append(String.format("  %-15s : %d%n", app, count)));
        return sb.toString();
    }

    private PacketAction classifyAndDecide(ParsedPacket pkt) {
        if (!pkt.isHasIp()) return PacketAction.FORWARD;

        FiveTuple tuple = pkt.toFiveTuple();
        Connection conn = connTracker.getOrCreateConnection(tuple);


        if (conn.getState() == ConnectionState.BLOCKED) {
            pkt.setAppType(conn.getAppType());
            pkt.setSni(conn.getSni());
            return PacketAction.DROP;
        }


        if (conn.getState() == ConnectionState.CLASSIFIED) {
            pkt.setAppType(conn.getAppType());
            pkt.setSni(conn.getSni());
        } else {

            String sni = null;
            if (pkt.getPayloadPreview() != null && pkt.isHasTcp() && pkt.getDstPort() == 443) {
                sni = sniExtractor.extract(pkt.getPayloadPreview());
            }

            AppType appType = AppType.UNKNOWN;
            if (sni != null) {
                appType = AppType.fromSni(sni);
            } else if (pkt.getDstPort() == 80) {
                appType = AppType.HTTP;
            } else if (pkt.getDstPort() == 443) {
                appType = AppType.HTTPS;
            } else if (pkt.getDstPort() == 53) {
                appType = AppType.DNS;
            }

            pkt.setAppType(appType);
            pkt.setSni(sni);

            if (appType != AppType.UNKNOWN || sni != null) {
                connTracker.classifyConnection(conn, appType, sni);
                conn.setAppType(appType);
                conn.setSni(sni);
            }
        }

        if (pkt.isHasTcp()) {
            int flags = pkt.getTcpFlags();
            if ((flags & PacketParserService.TCP_SYN) != 0 && !conn.isSynSeen()) {
                conn.setSynSeen(true);
            }
            if ((flags & PacketParserService.TCP_FIN) != 0) {
                connTracker.closeConnection(conn);
                return PacketAction.FORWARD;
            }
        }

        Optional<RuleManagerService.BlockReason> blockReason = ruleManager.shouldBlock(
                pkt.getSrcIp(),
                pkt.getDstPort(),
                pkt.getAppType(),
                pkt.getSni()
        );

        if (blockReason.isPresent()) {
            RuleManagerService.BlockReason reason = blockReason.get();
            log.debug("[DPIEngine] Blocking packet: {} ({}={})",
                    tuple, reason.type(), reason.detail());
            connTracker.blockConnection(conn);
            return PacketAction.DROP;
        }

        connTracker.updateConnection(conn, pkt.getPayloadLength(), true);
        return PacketAction.FORWARD;
    }

    private PcapGlobalHeader parsePcapGlobalHeader(byte[] data) {

        int b0 = data[0] & 0xFF;
        int b1 = data[1] & 0xFF;
        int b2 = data[2] & 0xFF;
        int b3 = data[3] & 0xFF;

        log.info("[DPIEngine] First 4 bytes: {:02X} {:02X} {:02X} {:02X}", b0, b1, b2, b3);

        boolean swapBytes;
        ByteOrder order;

        if ((b0 == 0xD4 && b1 == 0xC3 && b2 == 0xB2 && b3 == 0xA1) ||
                (b0 == 0x4D && b1 == 0x3C && b2 == 0xB2 && b3 == 0xA1)) {
            swapBytes = false;
            order = ByteOrder.LITTLE_ENDIAN;
            log.info("[DPIEngine] Detected little-endian PCAP");

        } else if ((b0 == 0xA1 && b1 == 0xB2 && b2 == 0xC3 && b3 == 0xD4) ||
                (b0 == 0xA1 && b1 == 0xB2 && b2 == 0x3C && b3 == 0x4D)) {
            swapBytes = true;
            order = ByteOrder.BIG_ENDIAN;
            log.info("[DPIEngine] Detected big-endian PCAP");

        } else {
            log.error("[DPIEngine] Unrecognized magic: {:02X} {:02X} {:02X} {:02X}", b0, b1, b2, b3);
            return null;
        }

        ByteBuffer buf = ByteBuffer.wrap(data);
        buf.order(order);
        buf.getInt();

        short versionMajor = buf.getShort();
        short versionMinor = buf.getShort();
        buf.getInt();
        buf.getInt();
        int snapLen  = buf.getInt();
        int linkType = buf.getInt();

        log.info("[DPIEngine] version={}.{}, linkType={}, snapLen={}, swapBytes={}",
                versionMajor, versionMinor, linkType, snapLen, swapBytes);

        return new PcapGlobalHeader(
                (b0 << 24) | (b1 << 16) | (b2 << 8) | b3,
                versionMajor, versionMinor, snapLen, linkType, swapBytes, data
        );
    }

    private PcapPacketHeader parsePcapPacketHeader(byte[] data, boolean swapBytes) {
        ByteBuffer buf = ByteBuffer.wrap(data);
        buf.order(swapBytes ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
        long tsSec   = buf.getInt() & 0xFFFFFFFFL;
        long tsUsec  = buf.getInt() & 0xFFFFFFFFL;
        int  inclLen = buf.getInt();
        int  origLen = buf.getInt();
        return new PcapPacketHeader(tsSec, tsUsec, inclLen, origLen);
    }

    private void writePcap(String outputPath, List<ParsedPacket> packets, PcapGlobalHeader header) {
        try (FileOutputStream fos = new FileOutputStream(outputPath)) {
            fos.write(header.rawBytes()); // write original global header
            log.info("[DPIEngine] Wrote {} forwarded packets to {}", packets.size(), outputPath);
        } catch (IOException e) {
            log.error("[DPIEngine] Failed to write output PCAP: {}", e.getMessage());
        }
    }

    private record PcapGlobalHeader(int magic, short versionMajor, short versionMinor,
                                    int snapLen, int linkType, boolean swapBytes,
                                    byte[] rawBytes) {}

    private record PcapPacketHeader(long tsSec, long tsUsec, int inclLen, int origLen) {}

    public record ProcessingResult(boolean success, String message,
                                   long totalPackets, long forwardedPackets,
                                   long droppedPackets) {}

    private CompletableFuture<ProcessingResult> result(boolean ok, String msg,
                                                       long t, long f, long d) {
        return CompletableFuture.completedFuture(new ProcessingResult(ok, msg, t, f, d));
    }
}