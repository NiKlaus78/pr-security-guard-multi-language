package com.security.guard.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;

/**
 * Fetches the unified diff for a GitHub PR and full file contents
 * for dependency manifests (pom.xml, package.json, requirements.txt).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class DiffExtractorService {

    private static final int MAX_DIFF_CHARS = 50_000;
    private static final int TIMEOUT_SECONDS = 30;

    @Value("${security-guard.github.token}")
    private String githubToken;

    @Value("${security-guard.github.api-base}")
    private String githubApiBase;

    private final WebClient webClient;

    public String fetchDiff(String repoFullName, Long prNumber) {
        log.debug("Fetching diff | repo={} PR=#{}", repoFullName, prNumber);

        String url = String.format("%s/repos/%s/pulls/%d", githubApiBase, repoFullName, prNumber);

        String rawDiff = webClient.get()
                .uri(url)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + githubToken)
                .header(HttpHeaders.ACCEPT, "application/vnd.github.diff")
                .retrieve()
                .bodyToMono(String.class)
                .timeout(Duration.ofSeconds(TIMEOUT_SECONDS))
                .onErrorResume(e -> {
                    log.error("Failed to fetch diff | repo={} PR=#{}", repoFullName, prNumber, e);
                    return Mono.just("");
                })
                .block();

        if (rawDiff == null || rawDiff.isBlank()) {
            log.warn("Empty diff received | repo={} PR=#{}", repoFullName, prNumber);
            return "";
        }

        log.info("Diff fetched | repo={} PR=#{} size={}chars", repoFullName, prNumber, rawDiff.length());

        if (rawDiff.length() > MAX_DIFF_CHARS) {
            log.warn("Diff truncated from {} to {} chars", rawDiff.length(), MAX_DIFF_CHARS);
            return truncateDiff(rawDiff);
        }

        return rawDiff;
    }

    public List<String> splitDiffByFile(String diff) {
        return List.of(diff.split("(?=diff --git )"))
                .stream()
                .filter(chunk -> !chunk.isBlank())
                .toList();
    }

    /**
     * Fetches the full raw content of a file from GitHub at a specific commit.
     * Used for dependency manifests: pom.xml, package.json, requirements.txt --
     * so CVE scanning covers ALL dependencies, not just newly added lines.
     */
    public String fetchFileContent(String repoFullName, String filePath, String ref) {
        String url = String.format("%s/repos/%s/contents/%s?ref=%s",
                githubApiBase, repoFullName, filePath, ref);

        try {
            String response = webClient.get()
                    .uri(url)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + githubToken)
                    .header(HttpHeaders.ACCEPT, "application/vnd.github.raw+json")
                    .retrieve()
                    .bodyToMono(String.class)
                    .timeout(Duration.ofSeconds(TIMEOUT_SECONDS))
                    .block();

            log.info("Fetched full file | repo={} file={} ref={}", repoFullName, filePath, ref);
            return response != null ? response : "";

        } catch (Exception e) {
            log.warn("Could not fetch full file | repo={} file={} error={}",
                    repoFullName, filePath, e.getMessage());
            return "";
        }
    }

    private String truncateDiff(String diff) {
        int cutPoint = diff.lastIndexOf("diff --git", MAX_DIFF_CHARS);
        if (cutPoint > MAX_DIFF_CHARS / 2) {
            return diff.substring(0, cutPoint)
                    + "\n\n[DIFF TRUNCATED — additional files omitted for context length]";
        }
        return diff.substring(0, MAX_DIFF_CHARS) + "\n\n[DIFF TRUNCATED]";
    }
}
