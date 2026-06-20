package com.dpi.controller;

import com.dpi.model.ParsedPacket;
import com.dpi.model.PacketAction;
import com.dpi.service.DpiEngineService;
import com.dpi.service.PacketParserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("/api/packets")
public class PacketController {

    private static final Logger log = LoggerFactory.getLogger(PacketController.class);

    private final DpiEngineService   dpiEngine;
    private final PacketParserService parserService;

    public PacketController(DpiEngineService dpiEngine, PacketParserService parserService) {
        this.dpiEngine     = dpiEngine;
        this.parserService = parserService;
    }


    @PostMapping("/analyze")
    public ResponseEntity<?> analyzePcap(@RequestParam("file") MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "No file provided"));
        }

        if (dpiEngine.isRunning()) {
            return ResponseEntity.status(409).body(Map.of("error", "Engine is already processing a file"));
        }

        // Save upload to temp file
        Path tempInput  = Files.createTempFile("dpi_input_", ".pcap");
        Path tempOutput = Files.createTempFile("dpi_output_", ".pcap");

        try {
            file.transferTo(tempInput.toFile());
            log.info("[PacketController] Received PCAP: {} ({} bytes)", file.getOriginalFilename(), file.getSize());

            CompletableFuture<DpiEngineService.ProcessingResult> future =
                    dpiEngine.processFile(tempInput.toString(), tempOutput.toString());

            DpiEngineService.ProcessingResult result = future.get();

            return ResponseEntity.ok(Map.of(
                    "success",          result.success(),
                    "message",          result.message(),
                    "totalPackets",     result.totalPackets(),
                    "forwardedPackets", result.forwardedPackets(),
                    "droppedPackets",   result.droppedPackets()
            ));
        } catch (Exception e) {
            log.error("Error processing PCAP: {}", e.getMessage());
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", e.getMessage()));
        } finally {
            Files.deleteIfExists(tempInput);
            Files.deleteIfExists(tempOutput);
        }
    }


    @PostMapping("/raw")
    public ResponseEntity<?> analyzeRawPacket(@RequestBody Map<String, String> body) {
        String hexData = body.get("data");
        if (hexData == null || hexData.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "No packet data provided (hex-encoded 'data' field)"));
        }

        byte[] rawData;
        try {
            rawData = hexToBytes(hexData.trim());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid hex data: " + e.getMessage()));
        }

        long now = Instant.now().getEpochSecond();
        PacketAction action = dpiEngine.processPacket(rawData, now, 0);

        ParsedPacket parsed = parserService.parse(rawData, now, 0);
        if (parsed == null) {
            return ResponseEntity.ok(Map.of("action", "DROP", "reason", "Parse failed"));
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("action",        action.name());
        response.put("srcIp",         parsed.getSrcIp());
        response.put("dstIp",         parsed.getDstIp());
        response.put("srcPort",       parsed.getSrcPort());
        response.put("dstPort",       parsed.getDstPort());
        response.put("protocol",      parsed.getProtocolName());
        response.put("appType",       parsed.getAppType().name());
        response.put("sni",           parsed.getSni());
        response.put("payloadBytes",  parsed.getPayloadLength());
        response.put("tcpFlags",      parsed.getTcpFlagsString());

        return ResponseEntity.ok(response);
    }


    @GetMapping("/status")
    public ResponseEntity<?> getStatus() {
        var snap = dpiEngine.getStats();
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("running",          dpiEngine.isRunning());
        resp.put("totalPackets",     snap.totalPackets());
        resp.put("totalBytes",       snap.totalBytes());
        resp.put("forwardedPackets", snap.forwardedPackets());
        resp.put("droppedPackets",   snap.droppedPackets());
        resp.put("tcpPackets",       snap.tcpPackets());
        resp.put("udpPackets",       snap.udpPackets());
        resp.put("otherPackets",     snap.otherPackets());
        resp.put("activeConnections",snap.activeConnections());
        return ResponseEntity.ok(resp);
    }


    @GetMapping("/report")
    public ResponseEntity<String> getReport() {
        return ResponseEntity.ok(dpiEngine.generateReport());
    }

    private byte[] hexToBytes(String hex) {
        if (hex.length() % 2 != 0) throw new IllegalArgumentException("Odd length hex string");
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int high = Character.digit(hex.charAt(i * 2),     16);
            int low  = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) throw new IllegalArgumentException("Non-hex character");
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }
}
