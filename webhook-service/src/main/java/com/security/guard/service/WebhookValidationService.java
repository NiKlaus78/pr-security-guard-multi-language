package com.security.guard.service;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.HmacUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class WebhookValidationService {

    @Value("${security-guard.github.webhook-secret}")
    private String webhookSecret;

    public boolean isValidSignature(String rawPayload, String signatureHeader) {
        if (signatureHeader == null || !signatureHeader.startsWith("sha256=")) {
            log.warn("Missing or malformed signature header");
            return false;
        }

        String receivedHex = signatureHeader.substring("sha256=".length());
        String computedHex = HmacUtils.hmacSha256Hex(webhookSecret, rawPayload);

        return constantTimeEquals(receivedHex, computedHex);
    }

    private boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) return false;

        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}
