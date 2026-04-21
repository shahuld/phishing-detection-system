package com.phishguard.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Response DTO for domain lookup results.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DomainLookupResponse {
    
    private String result;              // "domain-valid", "domain-suspicious", "domain-invalid", "error"
    private Double confidence;          // 0-100
    private String message;
    private DomainDetails details;
    private OwnershipInfo ownership;
    private Long timestamp;
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class DomainDetails {
        private String domain;
        private String domainName;      // Simple domain name without TLD
        private String tld;            // Top-level domain
        private Integer domainAgeDays;
        private Boolean isNewDomain;
        private Integer daysUntilExpiry;
        private String registrar;
        private String registrarUrl;
        private Boolean isKnownRegistrar;
        private String country;
        private String countryName;
        private Boolean isHighRiskCountry;
        private Boolean hasPrivacyProtection;
        private Integer nameserverCount;
        private List<String> nameServers;
        private Boolean hasDnssec;
        private String dnssecStatus;
        private Boolean isParked;
        private Boolean isForSale;
        private String domainStatus;
        private String creationDate;
        private String expiryDate;
        private String updatedDate;
        
        @SuppressWarnings("unchecked")
        public java.util.Map<String, Object> toMap() {
            java.util.Map<String, Object> map = new java.util.HashMap<>();
            map.put("domain", domain);
            map.put("domainName", domainName);
            map.put("tld", tld);
            map.put("domainAgeDays", domainAgeDays);
            map.put("isNewDomain", isNewDomain);
            map.put("daysUntilExpiry", daysUntilExpiry);
            map.put("registrar", registrar);
            map.put("registrarUrl", registrarUrl);
            map.put("isKnownRegistrar", isKnownRegistrar);
            map.put("country", country);
            map.put("countryName", countryName);
            map.put("isHighRiskCountry", isHighRiskCountry);
            map.put("hasPrivacyProtection", hasPrivacyProtection);
            map.put("nameserverCount", nameserverCount);
            map.put("nameServers", nameServers);
            map.put("hasDnssec", hasDnssec);
            map.put("dnssecStatus", dnssecStatus);
            map.put("isParked", isParked);
            map.put("isForSale", isForSale);
            map.put("domainStatus", domainStatus);
            map.put("creationDate", creationDate);
            map.put("expiryDate", expiryDate);
            map.put("updatedDate", updatedDate);
            return map;
        }
    }
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class OwnershipInfo {
        private String registrantName;
        private String registrantOrganization;
        private String registrantCountry;
        private String registrantCountryCode;
        private String registrantState;
        private String registrantCity;
        private String registrantEmail;      // May be hidden/redacted
        private String adminContactName;
        private String adminContactOrg;
        private String adminContactCountry;
        private String adminContactEmail;
        private String techContactName;
        private String techContactOrg;
        private String techContactEmail;
        private String billingContactName;
        private String billingContactEmail;
        private Boolean isPrivacyProtected;
        private String proxyService;         // If using privacy proxy
    }
    
    public static DomainLookupResponse valid(Double confidence, DomainDetails details) {
        return DomainLookupResponse.builder()
                .result("domain-valid")
                .confidence(confidence)
                .message("Domain appears legitimate")
                .details(details)
                .timestamp(System.currentTimeMillis())
                .build();
    }
    
    public static DomainLookupResponse suspicious(Double confidence, DomainDetails details) {
        return DomainLookupResponse.builder()
                .result("domain-suspicious")
                .confidence(confidence)
                .message("Domain shows suspicious characteristics")
                .details(details)
                .timestamp(System.currentTimeMillis())
                .build();
    }
    
    public static DomainLookupResponse suspicious(Double confidence, DomainDetails details, OwnershipInfo ownership) {
        return DomainLookupResponse.builder()
                .result("domain-suspicious")
                .confidence(confidence)
                .message("Domain shows suspicious characteristics")
                .details(details)
                .ownership(ownership)
                .timestamp(System.currentTimeMillis())
                .build();
    }
    
    public static DomainLookupResponse valid(Double confidence, DomainDetails details, OwnershipInfo ownership) {
        return DomainLookupResponse.builder()
                .result("domain-valid")
                .confidence(confidence)
                .message("Domain appears legitimate")
                .details(details)
                .ownership(ownership)
                .timestamp(System.currentTimeMillis())
                .build();
    }
    
    public static DomainLookupResponse error(String message) {
        return DomainLookupResponse.builder()
                .result("error")
                .confidence(0.0)
                .message(message)
                .timestamp(System.currentTimeMillis())
                .build();
    }
}
