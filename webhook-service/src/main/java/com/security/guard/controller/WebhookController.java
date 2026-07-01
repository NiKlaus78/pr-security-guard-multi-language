package com.security.guard.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.guard.model.GitHubPrPayload;
import com.security.guard.service.WebhookValidationService;
import com.security.guard.service.PrScanOrchestrator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/webhook")
@RequiredArgsConstructor
@Slf4j
public class WebhookController {

    private static final Set<String> SCAN_ACTIONS = Set.of("opened", "synchronize", "reopened");

    private final WebhookValidationService validationService;
    private final PrScanOrchestrator scanOrchestrator;
    private final ObjectMapper objectMapper;

    @PostMapping("/github")
    public ResponseEntity<Map<String, String>> handleGitHubWebhook(
            @RequestHeader(value = "X-Hub-Signature-256", required = false) String signature,
            @RequestHeader(value = "X-GitHub-Event", defaultValue = "unknown") String eventType,
            @RequestHeader(value = "X-GitHub-Delivery", defaultValue = "unknown") String deliveryId,
            @RequestBody String rawPayload) {

        log.info("Webhook received | event={} delivery={}", eventType, deliveryId);

        if (!validationService.isValidSignature(rawPayload, signature)) {
            log.warn("Invalid webhook signature | delivery={}", deliveryId);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid signature"));
        }

        if (!"pull_request".equals(eventType)) {
            log.debug("Skipping non-PR event: {}", eventType);
            return ResponseEntity.ok(Map.of("status", "skipped", "reason", "not a PR event"));
        }

        GitHubPrPayload payload;
        try {
            payload = objectMapper.readValue(rawPayload, GitHubPrPayload.class);
        } catch (Exception e) {
            log.error("Failed to parse PR payload | delivery={}", deliveryId, e);
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid payload format"));
        }

        String action = payload.getAction();
        if (!SCAN_ACTIONS.contains(action)) {
            log.debug("Skipping PR action: {}", action);
            return ResponseEntity.ok(Map.of("status", "skipped", "reason", "action=" + action));
        }

        log.info("Triggering security scan | repo={} PR=#{} action={}",
                payload.getRepository().getFullName(),
                payload.getPullRequest().getNumber(),
                action);

        scanOrchestrator.triggerScanAsync(payload);

        return ResponseEntity.ok(Map.of(
                "status", "accepted",
                "pr", String.valueOf(payload.getPullRequest().getNumber()),
                "message", "Security scan queued"
        ));
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of("status", "UP", "service", "pr-security-guard"));
    }
}
