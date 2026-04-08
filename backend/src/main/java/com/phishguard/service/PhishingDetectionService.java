package com.phishguard.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.phishguard.dto.*;
import com.phishguard.service.PythonExecutionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class PhishingDetectionService {

    private final PythonExecutionService pythonExecutionService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public UrlScanResponse scanUrl(UrlScanRequest request) {
        log.info("Scanning URL: {}", request.getUrl());
        try {
            Map<String, Object> mlResult = pythonExecutionService.detectUrl(request.getUrl());
            return mapToUrlScanResponse(mlResult);
        } catch (Exception e) {
            log.error("URL scan failed for {}: {}", request.getUrl(), e.getMessage());
            return UrlScanResponse.error("Scan failed: " + e.getMessage());
        }
    }

    public CertificateCheckResponse checkCertificate(CertificateCheckRequest request) {
        log.info("Checking certificate for domain: {}", request.getDomain());
        try {
            Map<String, Object> certData = new HashMap<>();
            certData.put("domain", request.getDomain());
            if (request.getHostname() != null) certData.put("hostname", request.getHostname());
            certData.put("port", request.getPort() != null ? request.getPort() : 443);

            Map<String, Object> mlResult = pythonExecutionService.detectCertificate(certData);
            return mapToCertificateResponse(mlResult);
        } catch (Exception e) {
            log.error("Certificate check failed for {}: {}", request.getDomain(), e.getMessage());
            return CertificateCheckResponse.error("Check failed: " + e.getMessage());
        }
    }

    public DomainLookupResponse lookupDomain(DomainLookupRequest request) {
        log.info("Domain lookup for: {}", request.getDomain());
        try {
            Map<String, Object> domainData = new HashMap<>();
            domainData.put("domain", request.getDomain());

            Map<String, Object> mlResult = pythonExecutionService.detectDomain(domainData);
            return mapToDomainLookupResponse(mlResult);
        } catch (Exception e) {
            log.error("Domain lookup failed for {}: {}", request.getDomain(), e.getMessage());
            return DomainLookupResponse.error("Lookup failed: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private UrlScanResponse mapToUrlScanResponse(Map<String, Object> mlResult) {
        String mlResultStr = (String) mlResult.getOrDefault("result", "unknown");
        Double confidence = ((Number) mlResult.getOrDefault("confidence", 0.0)).doubleValue();
        String message = (String) mlResult.getOrDefault("message", "Analysis complete");

        // Handle features - could be array or map
        Map<String, Object> features = new HashMap<>();
        Object featuresObj = mlResult.get("features");
        if (featuresObj instanceof Map) {
            features = (Map<String, Object>) featuresObj;
        } else if (featuresObj instanceof List) {
            // Convert array features to named map
            List<Object> featuresList = (List<Object>) featuresObj;
            String[] featureNames = {"url_length", "hostname_length", "path_length", "num_dots", "num_hyphens",
                "has_ip", "has_at_symbol", "is_suspicious_tld", "subdomain_count", "query_length", "has_email_in_url"};
            for (int i = 0; i < Math.min(featuresList.size(), featureNames.length); i++) {
                features.put(featureNames[i], featuresList.get(i));
            }
        }

        if ("phishing".equalsIgnoreCase(mlResultStr) || "malicious".equalsIgnoreCase(mlResultStr)) {
            return UrlScanResponse.phishing(confidence, features);
        } else if ("safe".equalsIgnoreCase(mlResultStr) || "legitimate".equalsIgnoreCase(mlResultStr)) {
            return UrlScanResponse.safe(confidence, features);
        } else {
            return UrlScanResponse.error(message);
        }
    }

    @SuppressWarnings("unchecked")
    private CertificateCheckResponse mapToCertificateResponse(Map<String, Object> mlResult) {
        log.info("Certificate ML result: {}", mlResult);
        String mlResultStr = ((String) mlResult.getOrDefault("result", "error")).toLowerCase();
        Double confidence = ((Number) mlResult.getOrDefault("confidence", 0.0)).doubleValue();
        String message = (String) mlResult.getOrDefault("message", "Certificate analysis complete");

        boolean isValid = mlResultStr.contains("valid") || mlResultStr.contains("safe");

        Map<String, Object> detailsMap = (Map<String, Object>) mlResult.getOrDefault("details", new HashMap<>());
        
        CertificateCheckResponse.CertificateDetails details = CertificateCheckResponse.CertificateDetails.builder()
                .isValid(isValid)
                .daysUntilExpiry((Integer) detailsMap.getOrDefault("days_to_expiry", 365))
                .issuer((String) detailsMap.getOrDefault("issuer", "Unknown"))
                .subject((String) detailsMap.getOrDefault("subject", "Unknown"))
                .keySize((Integer) detailsMap.getOrDefault("key_size", 2048))
                .hasChain((Boolean) detailsMap.getOrDefault("has_chain", true))
                .sanCount((Integer) detailsMap.getOrDefault("san_count", 1))
                .hasWildcard((Boolean) detailsMap.getOrDefault("wildcard", false))
                .signatureAlgorithm((String) detailsMap.getOrDefault("sig_alg", "SHA256"))
                .build();

        if (!isValid || mlResultStr.contains("phishing") || mlResultStr.contains("invalid")) {
            return CertificateCheckResponse.invalid(confidence, details);
        } else {
            return CertificateCheckResponse.valid(confidence, details);
        }
    }

    @SuppressWarnings("unchecked")
    private DomainLookupResponse mapToDomainLookupResponse(Map<String, Object> mlResult) {
        String mlResultStr = (String) mlResult.getOrDefault("result", "error");
        Double confidence = ((Number) mlResult.getOrDefault("confidence", 0.0)).doubleValue();
        String message = (String) mlResult.getOrDefault("message", "Domain analysis complete");

        Map<String, Object> detailsMap = (Map<String, Object>) mlResult.getOrDefault("details", new HashMap<>());
        DomainLookupResponse.DomainDetails details = DomainLookupResponse.DomainDetails.builder()
                .domain((String) detailsMap.getOrDefault("domain", "Unknown"))
                .domainName((String) detailsMap.getOrDefault("domain_name", "Unknown"))
                .tld((String) detailsMap.getOrDefault("tld", "Unknown"))
                .domainAgeDays((Integer) detailsMap.getOrDefault("age_days", 0))
                .isNewDomain((Boolean) detailsMap.getOrDefault("is_new", false))
                .daysUntilExpiry((Integer) detailsMap.getOrDefault("days_to_expiry", 0))
                .registrar((String) detailsMap.getOrDefault("registrar", "Unknown"))
                .registrarUrl((String) detailsMap.getOrDefault("registrar_url", ""))
                .isKnownRegistrar((Boolean) detailsMap.getOrDefault("known_registrar", false))
                .country((String) detailsMap.getOrDefault("country_code", "Unknown"))
                .countryName((String) detailsMap.getOrDefault("country", "Unknown"))
                .isHighRiskCountry((Boolean) detailsMap.getOrDefault("high_risk_country", false))
                .hasPrivacyProtection((Boolean) detailsMap.getOrDefault("privacy_protected", false))
                .nameserverCount((Integer) detailsMap.getOrDefault("ns_count", 0))
                .nameServers((List<String>) detailsMap.getOrDefault("name_servers", new ArrayList<>()))
                .hasDnssec((Boolean) detailsMap.getOrDefault("dnssec", false))
                .dnssecStatus((String) detailsMap.getOrDefault("dnssec_status", "Unknown"))
                .isParked((Boolean) detailsMap.getOrDefault("parked", false))
                .isForSale((Boolean) detailsMap.getOrDefault("for_sale", false))
                .domainStatus((String) detailsMap.getOrDefault("status", "Unknown"))
                .creationDate((String) detailsMap.getOrDefault("created", ""))
                .expiryDate((String) detailsMap.getOrDefault("expires", ""))
                .updatedDate((String) detailsMap.getOrDefault("updated", ""))
                .build();

        DomainLookupResponse.OwnershipInfo ownership = DomainLookupResponse.OwnershipInfo.builder()
                .registrantName((String) mlResult.getOrDefault("registrant_name", "Hidden"))
                .registrantOrganization((String) mlResult.getOrDefault("registrant_org", "Hidden"))
                .registrantCountry((String) mlResult.getOrDefault("registrant_country", "Unknown"))
                .registrantCountryCode((String) mlResult.getOrDefault("registrant_cc", "Unknown"))
                .isPrivacyProtected((Boolean) mlResult.getOrDefault("privacy", true))
                .build();

        if ("suspicious".equalsIgnoreCase(mlResultStr) || confidence > 70.0) {
            return DomainLookupResponse.suspicious(confidence, details, ownership);
        } else {
            return DomainLookupResponse.valid(confidence, details, ownership);
        }
    }
}

