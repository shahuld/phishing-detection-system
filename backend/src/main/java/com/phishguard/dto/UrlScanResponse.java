package com.phishguard.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * Response DTO for URL scanning results.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UrlScanResponse {
    
    private String result;          // "phishing", "safe", "error"
    private Double confidence;      // 0-100
    private String message;
    private Map<String, Object> features;
    private Long timestamp;
    
    public static UrlScanResponse phishing(Double confidence, Map<String, Object> features) {
        return UrlScanResponse.builder()
                .result("phishing")
                .confidence(confidence)
                .message("Phishing website detected")
                .features(features)
                .timestamp(System.currentTimeMillis())
                .build();
    }
    
    public static UrlScanResponse safe(Double confidence, Map<String, Object> features) {
        return UrlScanResponse.builder()
                .result("safe")
                .confidence(confidence)
                .message("Website appears safe")
                .features(features)
                .timestamp(System.currentTimeMillis())
                .build();
    }
    
    public static UrlScanResponse error(String message) {
        return UrlScanResponse.builder()
                .result("error")
                .confidence(0.0)
                .message(message)
                .timestamp(System.currentTimeMillis())
                .build();
    }
}
