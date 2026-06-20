package com.dpi.controller;

import com.dpi.model.AppType;
import com.dpi.model.Connection;
import com.dpi.model.ConnectionState;
import com.dpi.service.ConnectionTrackerService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;


@RestController
@RequestMapping("/api/connections")
public class ConnectionController {

    private final ConnectionTrackerService connTracker;

    public ConnectionController(ConnectionTrackerService connTracker) {
        this.connTracker = connTracker;
    }


    @GetMapping
    public ResponseEntity<List<Connection>> getRecentConnections() {
        return ResponseEntity.ok(connTracker.getRecentConnections());
    }

    @GetMapping("/state/{state}")
    public ResponseEntity<?> getByState(@PathVariable String state) {
        try {
            ConnectionState cs = ConnectionState.valueOf(state.toUpperCase());
            return ResponseEntity.ok(connTracker.getConnectionsByState(cs));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Unknown state: " + state));
        }
    }


    @GetMapping("/app/{app}")
    public ResponseEntity<?> getByApp(@PathVariable String app) {
        try {
            AppType appType = AppType.valueOf(app.toUpperCase());
            return ResponseEntity.ok(connTracker.getConnectionsByApp(appType));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Unknown app: " + app));
        }
    }


    @GetMapping("/stats")
    public ResponseEntity<?> getStats() {
        return ResponseEntity.ok(Map.of(
                "activeConnections", connTracker.getActiveConnectionCount(),
                "appDistribution",   connTracker.getAppDistribution()
        ));
    }
}
