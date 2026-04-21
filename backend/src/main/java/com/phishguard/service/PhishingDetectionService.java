package com.phishguard.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.phishguard.dto.*;
import com.phishguard.service.PythonExecutionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.MatchResult;

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
        String inputDomain = request.getUrl();
        String cleanDomain = extractDomain(inputDomain);
        log.info("Checking certificate for input '{}', extracted clean domain: {}", inputDomain, cleanDomain);
        try {
            Map<String, Object> certData = new HashMap<>();
            certData.put("domain", cleanDomain);
            if (request.getHostname() != null) certData.put("hostname", request.getHostname());
            certData.put("port", request.getPort() != null ? request.getPort() : 443);

            Map<String, Object> mlResult = pythonExecutionService.detectCertificate(certData);

            log.info("Raw cert ML result: {}", mlResult);
            CertificateCheckResponse response = mapToCertificateResponse(mlResult);
            log.info("Mapped cert response: result={}, confidence={}, valid={}", 
                     response.getResult(), response.getConfidence(), response.getDetails().isValid());
            return response;
        } catch (Exception e) {
            log.error("Certificate check failed for {}: {}", request.getUrl(), e.getMessage());
            return CertificateCheckResponse.error("Check failed: " + e.getMessage());
        }
    }

    public DomainLookupResponse lookupDomain(DomainLookupRequest request) {
        String inputDomain = request.getDomain();
        String cleanDomain = extractDomain(inputDomain);
        log.info("Domain lookup for input '{}', extracted clean domain: {}", inputDomain, cleanDomain);
        try {
            Map<String, Object> domainData = new HashMap<>();
            domainData.put("domain", cleanDomain);

            Map<String, Object> mlResult = pythonExecutionService.detectDomain(domainData);

            log.info("Raw domain ML result: {}", mlResult);
            DomainLookupResponse response = mapToDomainLookupResponse(mlResult);
            log.info("Mapped domain response: result={}, confidence={}, ageDays={}", 
                     response.getResult(), response.getConfidence(), response.getDetails().getDomainAgeDays());
            return response;
        } catch (Exception e) {
            log.error("Domain lookup failed for {}: {}", request.getDomain(), e.getMessage());
            return DomainLookupResponse.error("Lookup failed: " + e.getMessage());
        }
    }

    // FIXED: Combined scan logic update
    public CombinedScanResponse combinedScan(CombinedScanRequest request) {
        log.info("Combined scan for URL: {}", request.getUrl());
        String url = request.getUrl();
        String domain = extractDomain(url);
        
        try {
            UrlScanResponse urlResult = scanUrl(request);
            CertificateCheckRequest certReq = new CertificateCheckRequest();
            certReq.setUrl(domain);
            CertificateCheckResponse certResult = checkCertificate(certReq);
            DomainLookupRequest domainReq = new DomainLookupRequest();
            domainReq.setDomain(domain);
            DomainLookupResponse domainResult = lookupDomain(domainReq);
            
            // FIXED: Better safety check
            boolean urlSafe = "safe".equals(urlResult.getResult());
            boolean certValid = "certificate-valid".equals(certResult.getResult());
            boolean domainValid = "domain-valid".equals(domainResult.getResult());
            
            boolean allSafe = urlSafe && certValid && domainValid;
            Double avgConfidence = Math.max(0, (urlResult.getConfidence() + certResult.getConfidence() + domainResult.getConfidence()) / 3.0);
            
            Map<String, Object> combinedFeatures = mergeFeatures(
                urlResult.getFeatures() != null ? urlResult.getFeatures() : new HashMap<>(),
                certResult.getDetails().toMap(), 
                domainResult.getDetails().toMap()
            );
            
            if (allSafe) {
                return CombinedScanResponse.safe(avgConfidence, combinedFeatures, urlResult, certResult, domainResult);
            } else {
                return CombinedScanResponse.phishing(avgConfidence, combinedFeatures, urlResult, certResult, domainResult);
            }
        } catch (Exception e) {
            log.error("Combined scan failed for {}: {}", url, e.getMessage());
            return CombinedScanResponse.builder()
                    .result("error")
                    .confidence(0.0)
                    .message("Combined scan failed: " + e.getMessage())
                    .build();
        }
    }

    private String extractDomain(String url) {
        try {
            java.net.URL urlObj = new java.net.URL(url.startsWith("http") ? url : "https://" + url);
            return urlObj.getHost().replace("www.", "");
        } catch (Exception e) {
            String[] parts = url.split("/");
            return parts.length > 2 ? parts[2].replace("www.", "") : url;
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> mergeFeatures(Map<String, Object>... maps) {
        Map<String, Object> combined = new HashMap<>();
        for (Map<String, Object> map : maps) {
            if (map != null) combined.putAll(map);
        }
        return combined;
    }

    // UTILITY: Map snake_case to camelCase if needed (backup)
    private String toCamelCase(String snake) {
        if (snake == null) return null;
        StringBuilder sb = new StringBuilder(snake);
        for (int i = 0; i < sb.length() - 1; i++) {
            if (sb.charAt(i) == '_' ) {
                sb.deleteCharAt(i);
                if (i < sb.length()) {
                    sb.setCharAt(i, Character.toUpperCase(sb.charAt(i)));
                }
            }
        }
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> normalizeDetails(Map<String, Object> detailsMap, boolean isCert) {
        Map<String, Object> normalized = new HashMap<>();
        for (Map.Entry<String, Object> entry : detailsMap.entrySet()) {
            String key = entry.getKey();
            if (key.contains("_")) {
                normalized.put(toCamelCase(key), entry.getValue());
            } else {
                normalized.put(key, entry.getValue());
            }
        }
        return normalized;
    }

    @SuppressWarnings("unchecked")
    private UrlScanResponse mapToUrlScanResponse(Map<String, Object> mlResult) {
        String result = (String) mlResult.getOrDefault("result", "unknown");
        Double confidence = ((Number) mlResult.getOrDefault("confidence", 0.0)).doubleValue();
        String message = (String) mlResult.getOrDefault("message", "Analysis complete");

        Map<String, Object> features = new HashMap<>();
        Object featuresObj = mlResult.get("features");
        if (featuresObj instanceof List) {
            List<Object> list = (List<Object>) featuresObj;
            String[] names = {"url_length", "hostname_length", "path_length", "num_dots", "num_hyphens", "has_ip", "has_at_symbol", "is_suspicious_tld", "subdomain_count", "query_length", "has_email_in_url", "percent_encoding", "hex_escapes", "susp_keywords", "non_std_port"};
            for (int i = 0; i < Math.min(list.size(), names.length); i++) {
                features.put(names[i], list.get(i));
            }
        } else if (featuresObj instanceof Map) {
            features = (Map<String, Object>) featuresObj;
        }

        if ("phishing".equalsIgnoreCase(result)) {
            return UrlScanResponse.phishing(confidence, features);
        } else if ("safe".equalsIgnoreCase(result)) {
            return UrlScanResponse.safe(confidence, features);
        }
        return UrlScanResponse.error(message);
    }

    @SuppressWarnings("unchecked")
    private CertificateCheckResponse mapToCertificateResponse(Map<String, Object> mlResult) {
        String result = (String) mlResult.getOrDefault("result", "error");
        Double confidence = ((Number) mlResult.getOrDefault("confidence", 0.0)).doubleValue();
        String message = (String) mlResult.getOrDefault("message", "Certificate analysis complete");

        Map<String, Object> detailsMap = normalizeDetails((Map<String, Object>) mlResult.getOrDefault("details", new HashMap<>()), true);
        
        CertificateCheckResponse.CertificateDetails details = CertificateCheckResponse.CertificateDetails.builder()
            .isValid((Boolean) detailsMap.getOrDefault("isValid", true))
            .daysUntilExpiry((Integer) detailsMap.getOrDefault("daysUntilExpiry", 365))
            .issuer((String) detailsMap.getOrDefault("issuer", "Unknown"))
            .subject((String) detailsMap.getOrDefault("subject", "Unknown"))
            .keySize((Integer) detailsMap.getOrDefault("keySize", 2048))
            .hasChain((Boolean) detailsMap.getOrDefault("hasChain", true))
            .sanCount((Integer) detailsMap.getOrDefault("sanCount", 1))
            .hasWildcard((Boolean) detailsMap.getOrDefault("hasWildcard", false))
            .signatureAlgorithm((String) detailsMap.getOrDefault("signatureAlgorithm", "SHA256"))
            .build();

        log.debug("Cert details mapped: {}", detailsMap);

        // Use ML result directly - 'valid' means safe certificate, 'invalid' means suspicious
        if ("invalid".equals(result)) {
            return CertificateCheckResponse.invalid(confidence, details);
        }
        return CertificateCheckResponse.valid(confidence, details);
    }

    @SuppressWarnings("unchecked")
    private DomainLookupResponse mapToDomainLookupResponse(Map<String, Object> mlResult) {
        String result = (String) mlResult.getOrDefault("result", "error");
        Double confidence = ((Number) mlResult.getOrDefault("confidence", 0.0)).doubleValue();
        String message = (String) mlResult.getOrDefault("message", "Domain analysis complete");

        Map<String, Object> detailsMap = normalizeDetails((Map<String, Object>) mlResult.getOrDefault("details", new HashMap<>()), false);
        Map<String, Object> ownershipMap = (Map<String, Object>) detailsMap.getOrDefault("ownership", new HashMap<>());

        DomainLookupResponse.DomainDetails details = DomainLookupResponse.DomainDetails.builder()
            .domain((String) detailsMap.getOrDefault("domain", "Unknown"))
            .domainName((String) detailsMap.getOrDefault("domainName", "Unknown"))
            .tld((String) detailsMap.getOrDefault("tld", "Unknown"))
            .domainAgeDays((Integer) detailsMap.getOrDefault("domainAgeDays", 0))
            .isNewDomain((Boolean) detailsMap.getOrDefault("isNewDomain", false))
            .daysUntilExpiry((Integer) detailsMap.getOrDefault("daysUntilExpiry", 0))
            .registrar((String) detailsMap.getOrDefault("registrar", "Unknown"))
            .registrarUrl((String) detailsMap.getOrDefault("registrarUrl", ""))
            .isKnownRegistrar((Boolean) detailsMap.getOrDefault("isKnownRegistrar", false))
            .country((String) detailsMap.getOrDefault("country", "Unknown"))
            .countryName((String) detailsMap.getOrDefault("countryName", "Unknown"))
            .isHighRiskCountry((Boolean) detailsMap.getOrDefault("isHighRiskCountry", false))
            .hasPrivacyProtection((Boolean) detailsMap.getOrDefault("hasPrivacyProtection", false))
            .nameserverCount((Integer) detailsMap.getOrDefault("nameserverCount", 0))
            .nameServers((List<String>) detailsMap.getOrDefault("nameServers", new ArrayList<>()))
            .hasDnssec((Boolean) detailsMap.getOrDefault("hasDnssec", false))
            .dnssecStatus((String) detailsMap.getOrDefault("dnssecStatus", "Unknown"))
            .isParked((Boolean) detailsMap.getOrDefault("isParked", false))
            .isForSale((Boolean) detailsMap.getOrDefault("isForSale", false))
            .domainStatus((String) detailsMap.getOrDefault("domainStatus", "Unknown"))
            .creationDate((String) detailsMap.getOrDefault("creationDate", ""))
            .expiryDate((String) detailsMap.getOrDefault("expiryDate", ""))
            .updatedDate((String) detailsMap.getOrDefault("updatedDate", ""))
            .build();

        DomainLookupResponse.OwnershipInfo ownership = DomainLookupResponse.OwnershipInfo.builder()
            .registrantName((String) ownershipMap.getOrDefault("registrantName", "Hidden"))
            .registrantOrganization((String) ownershipMap.getOrDefault("registrantOrganization", "Hidden"))
            .registrantCountry((String) ownershipMap.getOrDefault("registrantCountry", "Unknown"))
            .registrantCountryCode((String) ownershipMap.getOrDefault("registrantCountryCode", "Unknown"))
            .isPrivacyProtected((Boolean) ownershipMap.getOrDefault("isPrivacyProtected", true))
            .build();

        log.debug("Domain details mapped: ageDays={}, registrar={}", details.getDomainAgeDays(), details.getRegistrar());

        // Use ML result directly - 'valid' means safe domain, 'suspicious' means risky
        if ("suspicious".equals(result)) {
            return DomainLookupResponse.suspicious(confidence, details, ownership);
        } 
        return DomainLookupResponse.valid(confidence, details, ownership);
    }
}
