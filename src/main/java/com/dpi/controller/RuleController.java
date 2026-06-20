package com.dpi.controller;

import com.dpi.model.AppType;
import com.dpi.service.RuleManagerService;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/rules")
public class RuleController {

    private final RuleManagerService ruleManager;

    public RuleController(RuleManagerService ruleManager) {
        this.ruleManager = ruleManager;
    }

    @GetMapping
    public ResponseEntity<?> getAllRules() {
        return ResponseEntity.ok(Map.of(
                "blockedIps",     ruleManager.getBlockedIps(),
                "blockedApps",    ruleManager.getBlockedApps(),
                "blockedDomains", ruleManager.getBlockedDomains(),
                "blockedPorts",   ruleManager.getBlockedPorts(),
                "stats",          ruleManager.getStats()
        ));
    }

    @PostMapping("/ip")
    public ResponseEntity<?> blockIp(@RequestBody Map<String, String> body) {
        String ip = body.get("ip");
        if (ip == null || ip.isBlank()) return ResponseEntity.badRequest().body(Map.of("error", "ip required"));
        ruleManager.blockIp(ip);
        return ResponseEntity.ok(Map.of("message", "Blocked IP: " + ip));
    }

    @DeleteMapping("/ip/{ip}")
    public ResponseEntity<?> unblockIp(@PathVariable String ip) {
        ruleManager.unblockIp(ip);
        return ResponseEntity.ok(Map.of("message", "Unblocked IP: " + ip));
    }

    @GetMapping("/ip/{ip}/check")
    public ResponseEntity<?> checkIp(@PathVariable String ip) {
        return ResponseEntity.ok(Map.of("ip", ip, "blocked", ruleManager.isIpBlocked(ip)));
    }

    @PostMapping("/app")
    public ResponseEntity<?> blockApp(@RequestBody Map<String, String> body) {
        String app = body.get("app");
        if (app == null || app.isBlank()) return ResponseEntity.badRequest().body(Map.of("error", "app required"));
        try {
            ruleManager.blockApp(AppType.valueOf(app.toUpperCase()));
            return ResponseEntity.ok(Map.of("message", "Blocked app: " + app.toUpperCase()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Unknown app: " + app,
                    "available", java.util.Arrays.toString(AppType.values())));
        }
    }

    @DeleteMapping("/app/{app}")
    public ResponseEntity<?> unblockApp(@PathVariable String app) {
        try {
            ruleManager.unblockApp(AppType.valueOf(app.toUpperCase()));
            return ResponseEntity.ok(Map.of("message", "Unblocked app: " + app.toUpperCase()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Unknown app: " + app));
        }
    }

    @PostMapping("/domain")
    public ResponseEntity<?> blockDomain(@RequestBody Map<String, String> body) {
        String domain = body.get("domain");
        if (domain == null || domain.isBlank()) return ResponseEntity.badRequest().body(Map.of("error", "domain required"));
        ruleManager.blockDomain(domain);
        return ResponseEntity.ok(Map.of("message", "Blocked domain: " + domain));
    }

    @DeleteMapping("/domain")
    public ResponseEntity<?> unblockDomain(@RequestBody Map<String, String> body) {
        String domain = body.get("domain");
        if (domain == null || domain.isBlank()) return ResponseEntity.badRequest().body(Map.of("error", "domain required"));
        ruleManager.unblockDomain(domain);
        return ResponseEntity.ok(Map.of("message", "Unblocked domain: " + domain));
    }

    @GetMapping("/domain/check")
    public ResponseEntity<?> checkDomain(@RequestParam String domain) {
        return ResponseEntity.ok(Map.of("domain", domain, "blocked", ruleManager.isDomainBlocked(domain)));
    }

    @PostMapping("/port")
    public ResponseEntity<?> blockPort(@RequestBody Map<String, Integer> body) {
        Integer port = body.get("port");
        if (port == null) return ResponseEntity.badRequest().body(Map.of("error", "port required"));
        if (port < 1 || port > 65535) return ResponseEntity.badRequest().body(Map.of("error", "port must be 1-65535"));
        ruleManager.blockPort(port);
        return ResponseEntity.ok(Map.of("message", "Blocked port: " + port));
    }

    @DeleteMapping("/port/{port}")
    public ResponseEntity<?> unblockPort(@PathVariable int port) {
        ruleManager.unblockPort(port);
        return ResponseEntity.ok(Map.of("message", "Unblocked port: " + port));
    }
}
