package com.dpi.service;

import com.dpi.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;


@Service
public class DpiEngineService {

    private static final Logger log = LoggerFactory.getLogger(DpiEngineService.class);


    private static final int PCAP_MAGIC_LE       = 0xD4C3B2A1;
    private static final int PCAP_MAGIC_BE       = 0xA1B2C3D4;
    private static final int PCAP_MAGIC_NS_LE    = 0x4D3CB2A1;
    private static final int PCAP_MAGIC_NS_BE    = 0xA1B23C4D;
    private static final int PCAP_GLOBAL_HDR_LEN = 24;
    private static final int PCAP_PKT_HDR_LEN    = 16;

    private final PacketParserService   parserService;
    private final SniExtractorService   sniExtractor;
    private final RuleManagerService    ruleManager;
    private final ConnectionTrackerService connTracker;
    private final DpiStats              stats;

    private final AtomicBoolean running    = new AtomicBoolean(false);
    private final AtomicLong    packetId   = new AtomicLong(0);


    private ExecutorService threadPool;

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

            log.info("[DPIEngine] PCAP link type: {}, snaplen: {}", header.linkType(), header.snapLen());

            List<ParsedPacket> forwardedPackets = new ArrayList<>();
            long total = 0, forwarded = 0, dropped = 0;

            // Read packets one at a time (mirrors C++ PcapReader::readNextPacket)
            byte[] pktHdr = new byte[PCAP_PKT_HDR_LEN];
            while (fis.read(pktHdr) == PCAP_PKT_HDR_LEN) {
                PcapPacketHeader ph = parsePcapPacketHeader(pktHdr, header.swapBytes());
                if (ph == null) break;

                byte[] rawData = fis.readNBytes(ph.inclLen());
                if (rawData.length < ph.inclLen()) break;

                total++;
                long id = packetId.incrementAndGet();

                // Parse the packet (mirrors C++ PacketParser::parse)
                ParsedPacket parsed = parserService.parse(rawData, ph.tsSec(), ph.tsUsec());
                if (parsed == null) {
                    log.debug("[DPIEngine] Failed to parse packet #{}", id);
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

            String msg = String.format("Processed %d packets: %d forwarded, %d dropped", total, forwarded, dropped);
            log.info("[DPIEngine] {}", msg);
            return result(true, msg, total, forwarded, dropped);

        } catch (IOException e) {
            log.error("[DPIEngine] Error processing file: {}", e.getMessage());
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
                return PacketAction.FORWARD; // Forward FIN packets
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

        // Update connection stats
        connTracker.updateConnection(conn, pkt.getPayloadLength(), true);

        return PacketAction.FORWARD;
    }

    private PcapGlobalHeader parsePcapGlobalHeader(byte[] data) {
        ByteBuffer buf = ByteBuffer.wrap(data);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        int magic = buf.getInt();

        boolean swapBytes;
        if (magic == PCAP_MAGIC_LE || magic == PCAP_MAGIC_NS_LE) {
            swapBytes = false;
        } else {
            buf.order(ByteOrder.BIG_ENDIAN);
            buf.position(0);
            magic = buf.getInt();
            if (magic == PCAP_MAGIC_BE || magic == PCAP_MAGIC_NS_BE) {
                swapBytes = true;
            } else {
                return null;
            }
        }

        short versionMajor = buf.getShort();
        short versionMinor = buf.getShort();
        buf.getInt(); // thiszone
        buf.getInt(); // sigfigs
        int snapLen  = buf.getInt();
        int linkType = buf.getInt();

        return new PcapGlobalHeader(magic, versionMajor, versionMinor, snapLen, linkType, swapBytes, data);
    }

    private PcapPacketHeader parsePcapPacketHeader(byte[] data, boolean swapBytes) {
        ByteBuffer buf = ByteBuffer.wrap(data);
        buf.order(swapBytes ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
        long tsSec  = buf.getInt() & 0xFFFFFFFFL;
        long tsUsec = buf.getInt() & 0xFFFFFFFFL;
        int  inclLen = buf.getInt();
        int  origLen = buf.getInt();
        return new PcapPacketHeader(tsSec, tsUsec, inclLen, origLen);
    }

    private void writePcap(String outputPath, List<ParsedPacket> packets, PcapGlobalHeader header) {
        try (FileOutputStream fos = new FileOutputStream(outputPath)) {

            fos.write(header.rawBytes());


            log.info("[DPIEngine] Wrote {} packets to {}", packets.size(), outputPath);
        } catch (IOException e) {
            log.error("[DPIEngine] Failed to write output PCAP: {}", e.getMessage());
        }
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

    private record PcapGlobalHeader(int magic, short versionMajor, short versionMinor,
                                    int snapLen, int linkType, boolean swapBytes, byte[] rawBytes) {}

    private record PcapPacketHeader(long tsSec, long tsUsec, int inclLen, int origLen) {}

    public record ProcessingResult(boolean success, String message,
                                   long totalPackets, long forwardedPackets, long droppedPackets) {}

    private CompletableFuture<ProcessingResult> result(boolean ok, String msg, long t, long f, long d) {
        return CompletableFuture.completedFuture(new ProcessingResult(ok, msg, t, f, d));
    }
}
