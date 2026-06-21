package com.dpi.repository;

import com.dpi.model.AppType;
import com.dpi.model.Connection;
import com.dpi.model.ConnectionState;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface ConnectionRepository extends JpaRepository<Connection, Long> {

    Optional<Connection> findBySrcIpAndDstIpAndSrcPortAndDstPortAndProtocol(
            String srcIp, String dstIp, int srcPort, int dstPort, int protocol);

    List<Connection> findByState(ConnectionState state);

    List<Connection> findByAppType(AppType appType);

    List<Connection> findBySrcIp(String srcIp);

    List<Connection> findByDstIp(String dstIp);

    @Query("SELECT c FROM Connection c WHERE c.lastSeen < :cutoff")
    List<Connection> findStaleConnections(@Param("cutoff") Instant cutoff);

    @Query("SELECT c.appType, COUNT(c) FROM Connection c GROUP BY c.appType ORDER BY COUNT(c) DESC")
    List<Object[]> countByAppType();

    @Query("SELECT COUNT(c) FROM Connection c WHERE c.state != com.dpi.model.ConnectionState.CLOSED")
    long countActiveConnections();

    List<Connection> findTop20ByOrderByLastSeenDesc();

    @Query("SELECT c FROM Connection c WHERE c.sni IS NOT NULL ORDER BY c.lastSeen DESC")
    List<Connection> findClassifiedConnections();
}
