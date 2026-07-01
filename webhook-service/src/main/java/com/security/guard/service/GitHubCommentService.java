package com.security.guard.service;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class GitHubCommentService {

    private static final String CONTEXT = "pr-security-guard";

    @Value("${security-guard.github.token}")
    private String githubToken;

    @Value("${security-guard.github.api-base}")
    private String githubApiBase;

    private final WebClient webClient;

    public void setPendingStatus(String repo, String sha, String description) {
        setCommitStatus(repo, sha, "pending", description);
    }

    public void setSuccessStatus(String repo, String sha, String description) {
        setCommitStatus(repo, sha, "success", description);
    }

    public void setFailureStatus(String repo, String sha, String description) {
        setCommitStatus(repo, sha, "failure", description);
    }

    public void setWarningStatus(String repo, String sha, String description) {
        setCommitStatus(repo, sha, "failure", "Warning: " + description);
    }

    private void setCommitStatus(String repo, String sha, String state, String description) {
        String url = String.format("%s/repos/%s/statuses/%s", githubApiBase, repo, sha);

        Map<String, String> body = Map.of(
                "state", state,
                "description", truncate(description, 140),
                "context", CONTEXT
        );

        try {
            webClient.post()
                    .uri(url)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + githubToken)
                    .header(HttpHeaders.ACCEPT, "application/vnd.github+json")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(body)
                    .retrieve()
                    .bodyToMono(String.class)
                    .timeout(Duration.ofSeconds(10))
                    .block();

            log.debug("Commit status set | repo={} sha={} state={}", repo, sha, state);
        } catch (Exception e) {
            log.error("Failed to set commit status | repo={} sha={}", repo, sha, e);
        }
    }

    public void postFindingComment(String repo, Long prNumber, String headSha, JsonNode finding) {
        postIssueComment(repo, prNumber, formatFindingAsComment(finding));
        log.debug("Posted finding to PR thread | repo={} PR=#{} type={} severity={}",
                repo, prNumber,
                finding.path("type").asText("unknown"),
                finding.path("severity").asText("unknown"));
    }

    public void postSummaryComment(String repo, Long prNumber, JsonNode findings, String decision) {
        StringBuilder sb = new StringBuilder();
        sb.append("## Security Guard Report\n\n");

        if ("BLOCK".equals(decision)) {
            sb.append("**This PR has been BLOCKED from merging** due to critical security violations.\n\n");
        } else {
            sb.append("**Security warnings found.** Review required before merging.\n\n");
        }

        sb.append("| Severity | Type | File | Action |\n");
        sb.append("|----------|------|------|--------|\n");

        for (JsonNode f : findings) {
            String gateAction = f.path("gate_action").asText();
            if ("DISCARD".equals(gateAction)) continue;

            String sev = f.path("severity").asText();
            String icon = switch (sev) {
                case "CRITICAL" -> "[CRIT]";
                case "HIGH"     -> "[HIGH]";
                case "MEDIUM"   -> "[MED]";
                default         -> "[LOW]";
            };
            String actionIcon = "BLOCK".equals(gateAction) ? "BLOCK" : "WARN";
            int line = f.path("line").asInt(0);
            String fileDisplay = line > 0
                    ? String.format("`%s:%d`", f.path("file").asText("unknown"), line)
                    : String.format("`%s`", f.path("file").asText("unknown"));

            sb.append(String.format("| %s %s | %s | %s | %s |\n",
                    icon, sev, f.path("type").asText(), fileDisplay, actionIcon));
        }

        sb.append("\n---\n*Auto-scanned by PR Security Guard*\n");

        postIssueComment(repo, prNumber, sb.toString());
    }

    private void postIssueComment(String repo, Long prNumber, String body) {
        String url = String.format("%s/repos/%s/issues/%d/comments", githubApiBase, repo, prNumber);

        try {
            webClient.post()
                    .uri(url)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + githubToken)
                    .header(HttpHeaders.ACCEPT, "application/vnd.github+json")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("body", body))
                    .retrieve()
                    .bodyToMono(String.class)
                    .timeout(Duration.ofSeconds(10))
                    .block();
        } catch (Exception e) {
            log.error("Failed to post PR comment | repo={} PR=#{}", repo, prNumber, e);
        }
    }

    private String formatFindingAsComment(JsonNode f) {
        String severity = f.path("severity").asText("UNKNOWN");
        String icon = switch (severity) {
            case "CRITICAL" -> "**CRITICAL**";
            case "HIGH"     -> "**HIGH**";
            case "MEDIUM"   -> "**MEDIUM**";
            default         -> "**LOW**";
        };

        int line = f.path("line").asInt(0);
        String location = line > 0
                ? String.format("`%s` line %d", f.path("file").asText("unknown"), line)
                : String.format("`%s`", f.path("file").asText("unknown"));

        return String.format("""
                %s — %s

                **Location:** %s

                **What was found:** %s

                **Evidence:**
                ```
                %s
                ```

                **Remediation:** %s

                **Policy reference:** `%s`
                **Confidence:** %.0f%%  |  **Verdict:** %s

                ---
                *Auto-reviewed by PR Security Guard*
                """,
                icon,
                f.path("type").asText(),
                location,
                f.path("type").asText().replace("_", " ").toLowerCase(),
                f.path("evidence").asText(),
                f.path("remediation").asText("Remove and use environment variables."),
                f.path("policy_ref").asText("SEC-001"),
                f.path("final_confidence").asDouble(0) * 100,
                f.path("critique_verdict").asText("CONFIRMED")
        );
    }

    private String truncate(String s, int max) {
        return s.length() > max ? s.substring(0, max - 3) + "..." : s;
    }
}
