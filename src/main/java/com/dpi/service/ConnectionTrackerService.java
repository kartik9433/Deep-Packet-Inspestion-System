package com.dpi.service;

import com.dpi.model.*;
import com.dpi.repository.ConnectionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;


@Service
public class ConnectionTrackerService {

    private static final Logger log = LoggerFactory.getLogger(ConnectionTrackerService.class);
    private static final long CONNECTION_TIMEOUT_SECONDS = 300;

    private final ConnectionRepository connectionRepo;
    private final DpiStats stats;

    public ConnectionTrackerService(ConnectionRepository connectionRepo, DpiStats stats) {
        this.connectionRepo = connectionRepo;
        this.stats = stats;
    }

    @Transactional
    public Connection getOrCreateConnection(FiveTuple tuple) {
        return findConnection(tuple).orElseGet(() -> {
            Connection conn = new Connection(tuple);
            conn = connectionRepo.save(conn);
            stats.incrementActiveConnections();
            log.debug("[Tracker] New connection: {}", tuple);
            return conn;
        });
    }


    public Optional<Connection> findConnection(FiveTuple tuple) {
        Optional<Connection> conn = connectionRepo.findBySrcIpAndDstIpAndSrcPortAndDstPortAndProtocol(
                tuple.getSrcIp(), tuple.getDstIp(), tuple.getSrcPort(), tuple.getDstPort(), tuple.getProtocol());
        if (conn.isPresent()) return conn;

        FiveTuple rev = tuple.reverse();
        return connectionRepo.findBySrcIpAndDstIpAndSrcPortAndDstPortAndProtocol(
                rev.getSrcIp(), rev.getDstIp(), rev.getSrcPort(), rev.getDstPort(), rev.getProtocol());
    }


    @Transactional
    public void updateConnection(Connection conn, long packetSize, boolean isOutbound) {
        if (isOutbound) {
            conn.setPacketsOut(conn.getPacketsOut() + 1);
            conn.setBytesOut(conn.getBytesOut() + packetSize);
        } else {
            conn.setPacketsIn(conn.getPacketsIn() + 1);
            conn.setBytesIn(conn.getBytesIn() + packetSize);
        }
        conn.touch();

        if (conn.getState() == ConnectionState.NEW) {
            conn.setState(ConnectionState.ESTABLISHED);
        }
        connectionRepo.save(conn);
    }


    @Transactional
    public void classifyConnection(Connection conn, AppType appType, String sni) {
        conn.setAppType(appType);
        conn.setSni(sni);
        conn.setState(ConnectionState.CLASSIFIED);
        connectionRepo.save(conn);
        log.debug("[Tracker] Classified {} as {} (sni={})", conn.toFiveTuple(), appType, sni);
    }


    @Transactional
    public void blockConnection(Connection conn) {
        conn.setState(ConnectionState.BLOCKED);
        conn.setAction(PacketAction.DROP);
        connectionRepo.save(conn);
    }


    @Transactional
    public void closeConnection(Connection conn) {
        conn.setState(ConnectionState.CLOSED);
        conn.setFinSeen(true);
        connectionRepo.save(conn);
        stats.decrementActiveConnections();
    }


    public List<Connection> getRecentConnections() {
        return connectionRepo.findTop20ByOrderByLastSeenDesc();
    }

    public List<Connection> getConnectionsByState(ConnectionState state) {
        return connectionRepo.findByState(state);
    }

    public List<Connection> getConnectionsByApp(AppType appType) {
        return connectionRepo.findByAppType(appType);
    }

    public Map<AppType, Long> getAppDistribution() {
        return connectionRepo.countByAppType().stream()
                .collect(Collectors.toMap(
                        row -> (AppType) row[0],
                        row -> (Long) row[1]
                ));
    }

    public long getActiveConnectionCount() {
        return connectionRepo.countActiveConnections();
    }

    @Scheduled(fixedDelay = 60_000)
    @Transactional
    public void cleanupStaleConnections() {
        Instant cutoff = Instant.now().minusSeconds(CONNECTION_TIMEOUT_SECONDS);
        List<Connection> stale = connectionRepo.findStaleConnections(cutoff);
        for (Connection conn : stale) {
            if (conn.getState() != ConnectionState.CLOSED) {
                conn.setState(ConnectionState.CLOSED);
                connectionRepo.save(conn);
                stats.decrementActiveConnections();
            }
        }
        if (!stale.isEmpty()) {
            log.info("[Tracker] Cleaned up {} stale connections", stale.size());
        }
    }
}
