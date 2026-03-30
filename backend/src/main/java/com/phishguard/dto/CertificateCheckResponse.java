package com.phishguard.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response DTO for certificate checking results.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateCheckResponse {
    
    private String result;              // "certificate-valid", "certificate-invalid", "error"
    private Double confidence;          // 0-100
    private String message;
    private CertificateDetails details;
    private Long timestamp;
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CertificateDetails {
        private Boolean isValid;
        private Integer daysUntilExpiry;
        private String issuer;
        private String subject;
        private Integer keySize;
        private Boolean hasChain;
        private Integer sanCount;
        private Boolean hasWildcard;
        private String signatureAlgorithm;
    }
    
    public static CertificateCheckResponse valid(Double confidence, CertificateDetails details) {
        return CertificateCheckResponse.builder()
                .result("certificate-valid")
                .confidence(confidence)
                .message("Certificate is valid")
                .details(details)
                .timestamp(System.currentTimeMillis())
                .build();
    }
    
    public static CertificateCheckResponse invalid(Double confidence, CertificateDetails details) {
        return CertificateCheckResponse.builder()
                .result("certificate-invalid")
                .confidence(confidence)
                .message("Certificate issue found")
                .details(details)
                .timestamp(System.currentTimeMillis())
                .build();
    }
    
    public static CertificateCheckResponse error(String message) {
        return CertificateCheckResponse.builder()
                .result("error")
                .confidence(0.0)
                .message(message)
                .timestamp(System.currentTimeMillis())
                .build();
    }
}
