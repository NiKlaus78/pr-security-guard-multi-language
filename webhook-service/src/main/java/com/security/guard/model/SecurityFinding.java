package com.security.guard.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Table(name = "security_findings")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityFinding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "repo_full_name", nullable = false)
    private String repoFullName;

    @Column(name = "pr_number", nullable = false)
    private Long prNumber;

    @Column(name = "pr_author")
    private String prAuthor;

    @Column(name = "head_sha", nullable = false)
    private String headSha;

    @Column(name = "finding_id", nullable = false)
    private String findingId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity;

    @Column(name = "finding_type", nullable = false)
    private String findingType;

    @Column(name = "file_path")
    private String filePath;

    @Column(name = "line_number")
    private Integer lineNumber;

    @Column(columnDefinition = "TEXT")
    private String evidence;

    @Column(columnDefinition = "TEXT")
    private String remediation;

    @Column(name = "policy_ref")
    private String policyRef;

    @Column(name = "initial_confidence")
    private Double initialConfidence;

    @Column(name = "final_confidence")
    private Double finalConfidence;

    @Column(name = "critique_verdict")
    private String critiqueVerdict;

    @Column(name = "critique_rationale", columnDefinition = "TEXT")
    private String critiqueRationale;

    @Enumerated(EnumType.STRING)
    @Column(name = "gate_action")
    private GateAction gateAction;

    @Column(name = "langsmith_run_id")
    private String langsmithRunId;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
    }

    public enum Severity {
        CRITICAL, HIGH, MEDIUM, LOW
    }

    public enum GateAction {
        BLOCK, WARN, DISCARD
    }
}
