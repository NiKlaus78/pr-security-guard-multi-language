package com.security.guard.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.guard.model.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Orchestrates the full PR security scan pipeline.
 *
 * Detects and fetches THREE possible dependency manifests so CVE scanning
 * works across languages in the same PR (e.g. a monorepo with Java + Node + Python):
 *   pom.xml          -> Maven (Java)
 *   package.json     -> npm (JavaScript / Node.js)
 *   requirements.txt -> PyPI (Python)
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PrScanOrchestrator {

    @Value("${security-guard.agent.service-url}")
    private String agentServiceUrl;

    @Value("${security-guard.agent.timeout-seconds:120}")
    private int agentTimeoutSeconds;

    private final DiffExtractorService diffExtractorService;
    private final GitHubCommentService commentService;
    private final SecurityFindingRepository findingRepository;
    private final WebClient webClient;
    private final ObjectMapper objectMapper;

    @Async
    public void triggerScanAsync(GitHubPrPayload payload) {
        String repoFullName = payload.getRepository().getFullName();
        Long prNumber = payload.getPullRequest().getNumber();
        String headSha = payload.getPullRequest().getHead().getSha();

        log.info("=== Starting security scan | repo={} PR=#{} ===", repoFullName, prNumber);

        try {
            commentService.setPendingStatus(repoFullName, headSha, "PR Security Guard is scanning...");

            String diffContent = diffExtractorService.fetchDiff(repoFullName, prNumber);

            if (diffContent.isBlank()) {
                log.warn("No diff content found | repo={} PR=#{}", repoFullName, prNumber);
                commentService.setSuccessStatus(repoFullName, headSha, "No diff to scan.");
                return;
            }

            // ── Fetch all applicable dependency manifests ─────────────────
            String pomXmlContent = fetchManifestIfPresent(diffContent, repoFullName, headSha, "pom.xml");
            String packageJsonContent = fetchManifestIfPresent(diffContent, repoFullName, headSha, "package.json");
            String requirementsTxtContent = fetchManifestIfPresent(diffContent, repoFullName, headSha, "requirements.txt");

            AgentScanRequest request = AgentScanRequest.builder()
                    .prNumber(prNumber)
                    .repoFullName(repoFullName)
                    .headSha(headSha)
                    .baseSha(payload.getPullRequest().getBase().getSha())
                    .prAuthor(payload.getPullRequest().getUser().getLogin())
                    .prTitle(payload.getPullRequest().getTitle())
                    .diffContent(diffContent)
                    .pomXmlContent(pomXmlContent)
                    .packageJsonContent(packageJsonContent)
                    .requirementsTxtContent(requirementsTxtContent)
                    .build();

            log.info("Calling agent service | repo={} PR=#{}", repoFullName, prNumber);
            String agentResponseJson = callAgentService(request);

            JsonNode response = objectMapper.readTree(agentResponseJson);
            String gateDecision = response.path("gate_decision").asText("ALLOW");
            String langsmithRunId = response.path("langsmith_run_id").asText("");
            JsonNode findings = response.path("findings");

            log.info("Agent scan complete | repo={} PR=#{} decision={} findings={}",
                    repoFullName, prNumber, gateDecision, findings.size());

            List<SecurityFinding> persistedFindings = new ArrayList<>();
            for (JsonNode finding : findings) {
                String gateAction = finding.path("gate_action").asText("DISCARD");

                if (!"DISCARD".equals(gateAction)) {
                    commentService.postFindingComment(repoFullName, prNumber, headSha, finding);
                }

                SecurityFinding entity = buildFindingEntity(
                        finding, repoFullName, prNumber,
                        payload.getPullRequest().getUser().getLogin(),
                        headSha, langsmithRunId);
                persistedFindings.add(entity);
            }

            findingRepository.saveAll(persistedFindings);

            if ("BLOCK".equals(gateDecision)) {
                long criticalCount = countBySeverity(findings, "CRITICAL");
                long highCount = countBySeverity(findings, "HIGH");
                String description = String.format(
                        "BLOCKED: %d critical, %d high severity findings.", criticalCount, highCount);
                commentService.setFailureStatus(repoFullName, headSha, description);
                commentService.postSummaryComment(repoFullName, prNumber, findings, gateDecision);

            } else if ("WARN".equals(gateDecision)) {
                commentService.setWarningStatus(repoFullName, headSha, "Security warnings found. Review required.");
                commentService.postSummaryComment(repoFullName, prNumber, findings, gateDecision);

            } else {
                commentService.setSuccessStatus(repoFullName, headSha, "No security violations detected.");
            }

            log.info("=== Scan complete | repo={} PR=#{} decision={} ===", repoFullName, prNumber, gateDecision);

        } catch (Exception e) {
            log.error("Scan failed | repo={} PR=#{}", repoFullName, prNumber, e);
            commentService.setFailureStatus(repoFullName, headSha, "Security scan failed. Check guard service logs.");
        }
    }

    /**
     * If the given manifest filename appears anywhere in the diff, extracts
     * its actual repo-relative path (handles monorepo layouts) and fetches
     * the full file content from GitHub. Returns empty string if not present.
     */
    private String fetchManifestIfPresent(String diffContent, String repoFullName,
                                            String headSha, String manifestFilename) {
        if (!diffContent.contains(manifestFilename)) {
            return "";
        }

        String manifestPath = extractManifestPath(diffContent, manifestFilename);
        log.info("{} detected at '{}' — fetching full file | repo={}",
                manifestFilename, manifestPath, repoFullName);

        return diffExtractorService.fetchFileContent(repoFullName, manifestPath, headSha);
    }

    /**
     * Extracts the actual file path from a unified diff header.
     * Handles cases where the manifest is in a subdirectory
     * (e.g. "node-service/package.json" not just "package.json").
     */
    private String extractManifestPath(String diffContent, String filename) {
        for (String line : diffContent.split("\n")) {
            if (line.startsWith("diff --git") && line.contains(filename)) {
                String[] parts = line.split(" ");
                for (String part : parts) {
                    if (part.startsWith("b/") && part.endsWith(filename)) {
                        return part.substring(2);
                    }
                }
            }
        }
        return filename;
    }

    private String callAgentService(AgentScanRequest request) throws Exception {
        String requestJson = objectMapper.writeValueAsString(request);

        return webClient.post()
                .uri(agentServiceUrl + "/scan")
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .bodyValue(requestJson)
                .retrieve()
                .bodyToMono(String.class)
                .timeout(Duration.ofSeconds(agentTimeoutSeconds))
                .block();
    }

    private long countBySeverity(JsonNode findings, String severity) {
        long count = 0;
        for (JsonNode f : findings) {
            if (severity.equals(f.path("severity").asText()) &&
                !"DISCARD".equals(f.path("gate_action").asText())) {
                count++;
            }
        }
        return count;
    }

    private SecurityFinding buildFindingEntity(
            JsonNode f, String repo, Long prNumber, String author,
            String headSha, String langsmithRunId) {

        return SecurityFinding.builder()
                .repoFullName(repo)
                .prNumber(prNumber)
                .prAuthor(author)
                .headSha(headSha)
                .findingId(f.path("finding_id").asText())
                .severity(parseSeverity(f.path("severity").asText()))
                .findingType(f.path("type").asText())
                .filePath(f.path("file").asText())
                .lineNumber(f.path("line").asInt(0))
                .evidence(f.path("evidence").asText())
                .remediation(f.path("remediation").asText())
                .policyRef(f.path("policy_ref").asText())
                .initialConfidence(f.path("initial_confidence").asDouble())
                .finalConfidence(f.path("final_confidence").asDouble())
                .critiqueVerdict(f.path("critique_verdict").asText())
                .critiqueRationale(f.path("critique_rationale").asText())
                .gateAction(parseGateAction(f.path("gate_action").asText()))
                .langsmithRunId(langsmithRunId)
                .build();
    }

    private SecurityFinding.Severity parseSeverity(String s) {
        try { return SecurityFinding.Severity.valueOf(s); }
        catch (Exception e) { return SecurityFinding.Severity.MEDIUM; }
    }

    private SecurityFinding.GateAction parseGateAction(String s) {
        try { return SecurityFinding.GateAction.valueOf(s); }
        catch (Exception e) { return SecurityFinding.GateAction.DISCARD; }
    }
}
