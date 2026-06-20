package com.dpi.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

@Entity
@Table(name = "blocking_rules")
@Getter
@Setter
@NoArgsConstructor
@ToString
public class BlockingRule {

    public enum RuleType { IP, APP, DOMAIN, PORT }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "rule_type", nullable = false)
    private RuleType ruleType;

    @Column(name = "rule_value", nullable = false)
    private String value;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "description")
    private String description;

    @Column(name = "active", nullable = false)
    private boolean active = true;

    // Custom constructors — Lombok can't generate these
    public BlockingRule(RuleType ruleType, String value) {
        this.ruleType = ruleType;
        this.value = value;
    }

    public BlockingRule(RuleType ruleType, String value, String description) {
        this.ruleType = ruleType;
        this.value = value;
        this.description = description;
    }
}