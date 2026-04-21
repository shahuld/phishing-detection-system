package com.phishguard.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * Response DTO for combined scan results from all three services.
 * Final verdict: "safe" only if ALL services safe/valid, else "phishing".
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CombinedScanResponse {
    
    // Final combined result
    private String result;              // "safe" or "phishing"
    private Double confidence;          // Average confidence
    private String message;             // Summary message
    
    // Individual service results for transparency
    private UrlScanResponse mlResult;           // URL/ML phishing detection
    private CertificateCheckResponse certResult; // Certificate validity
    private DomainLookupResponse domainResult;  // Domain reputation
    
    // Combined features/details
    private Map<String, Object> features;
    private String details;                 // Detailed explanation of verdict
    
    public static CombinedScanResponse safe(Double confidence, Map<String, Object> features,
                                          UrlScanResponse ml, CertificateCheckResponse cert, DomainLookupResponse domain) {
        return CombinedScanResponse.builder()
                .result("safe")
                .confidence(confidence)
                .message("All services confirm website is safe")
                .mlResult(ml)
                .certResult(cert)
                .domainResult(domain)
                .features(features)
                .details("ML: safe, Certificate: valid, Domain: legitimate")
                .build();
    }
    
    public static CombinedScanResponse phishing(Double confidence, Map<String, Object> features,
                                              UrlScanResponse ml, CertificateCheckResponse cert, DomainLookupResponse domain) {
        return CombinedScanResponse.builder()
                .result("phishing")
                .confidence(confidence)
                .message("One or more services detected phishing risk")
                .mlResult(ml)
                .certResult(cert)
                .domainResult(domain)
                .features(features)
                .details(getPhishingDetails(ml, cert, domain))
                .build();
    }
    
    private static String getPhishingDetails(UrlScanResponse ml, CertificateCheckResponse cert, DomainLookupResponse domain) {
        StringBuilder details = new StringBuilder("Risk factors: ");
        if ("phishing".equals(ml.getResult())) details.append("ML detected phishing patterns; ");
        if (!cert.getDetails().isValid()) details.append("Invalid certificate; ");
        if ("suspicious".equals(domain.getResult()) || domain.getConfidence() > 70) details.append("Suspicious domain; ");
        return details.toString();
    }
}

