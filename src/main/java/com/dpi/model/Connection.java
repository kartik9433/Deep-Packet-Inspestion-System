package com.dpi.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

@Entity
@Table(name = "connections")
@Getter
@Setter
@NoArgsConstructor
@ToString
public class Connection {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "src_ip", nullable = false)
    private String srcIp;

    @Column(name = "dst_ip", nullable = false)
    private String dstIp;

    @Column(name = "src_port", nullable = false)
    private int srcPort;

    @Column(name = "dst_port", nullable = false)
    private int dstPort;

    @JsonIgnore
    @Column(name = "protocol", nullable = false)
    private int protocol;

    @Enumerated(EnumType.STRING)
    @Column(name = "state", nullable = false)
    private ConnectionState state = ConnectionState.NEW;

    @Enumerated(EnumType.STRING)
    @Column(name = "app_type", nullable = false)
    private AppType appType = AppType.UNKNOWN;

    @Column(name = "sni")
    private String sni;

    @Column(name = "packets_in")
    private long packetsIn = 0;

    @Column(name = "packets_out")
    private long packetsOut = 0;

    @Column(name = "bytes_in")
    private long bytesIn = 0;

    @Column(name = "bytes_out")
    private long bytesOut = 0;

    @Column(name = "first_seen", nullable = false)
    private Instant firstSeen = Instant.now();

    @Column(name = "last_seen", nullable = false)
    private Instant lastSeen = Instant.now();

    @Enumerated(EnumType.STRING)
    @Column(name = "action", nullable = false)
    private PacketAction action = PacketAction.FORWARD;

    @Column(name = "syn_seen")
    private boolean synSeen = false;

    @Column(name = "syn_ack_seen")
    private boolean synAckSeen = false;

    @Column(name = "fin_seen")
    private boolean finSeen = false;

    // Custom constructor
    public Connection(FiveTuple tuple) {
        this.srcIp    = tuple.getSrcIp();
        this.dstIp    = tuple.getDstIp();
        this.srcPort  = tuple.getSrcPort();
        this.dstPort  = tuple.getDstPort();
        this.protocol = tuple.getProtocol();
    }

    // Custom methods — not boilerplate
    public String getProtocolName() {
        return switch (protocol) {
            case 1  -> "ICMP";
            case 6  -> "TCP";
            case 17 -> "UDP";
            default -> "OTHER";
        };
    }

    public FiveTuple toFiveTuple() {
        return new FiveTuple(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    public void touch() {
        this.lastSeen = Instant.now();
    }

    public boolean isStale(long timeoutSeconds) {
        return lastSeen.isBefore(Instant.now().minusSeconds(timeoutSeconds));
    }
}