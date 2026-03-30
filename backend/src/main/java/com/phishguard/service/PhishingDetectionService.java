package com.phishguard.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.phishguard.dto.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Service layer for phishing detection.
 * Integrates with Python ML scripts directly for ML-based detection.
 */
@Service
public class PhishingDetectionService {
    
    private static final Logger logger = LoggerFactory.getLogger(PhishingDetectionService.class);
    
    // Known legitimate registrars for comparison
    private static final Set<String> KNOWN_REGISTRARS = new HashSet<>(Arrays.asList(
        "godaddy", "namecheap", "enom", "register", "network solutions", 
        "csc corporate", "markmonitor", "easy dns", "cloudflare", "domain.com",
        "dreamhost", "hover", "gandi", "name.com", "Dynadot", "uniregistry",
        " Tucows", "melbourne it", "key-systems", " abuser"
    ));
    
    // High-risk countries for domain registration
    private static final Set<String> HIGH_RISK_COUNTRIES = new HashSet<>(Arrays.asList(
        "CN", "RU", "UA", "BY", "KZ", "KG", "TJ", "TM", "UZ", "KP", "IR", "SY", 
        "YE", "VE", "CU", "ZW", "BI", "CF", "CD", "CG", "GQ", "GA", "SZ", 
        "ZW", "LY", "PK" // Pakistan is sometimes flagged
    ));
    
    // Country code to name mapping
    private static final Map<String, String> COUNTRY_NAMES = new HashMap<>();
    static {
        COUNTRY_NAMES.put("US", "United States");
        COUNTRY_NAMES.put("GB", "United Kingdom");
        COUNTRY_NAMES.put("CA", "Canada");
        COUNTRY_NAMES.put("AU", "Australia");
        COUNTRY_NAMES.put("DE", "Germany");
        COUNTRY_NAMES.put("FR", "France");
        COUNTRY_NAMES.put("JP", "Japan");
        COUNTRY_NAMES.put("CN", "China");
        COUNTRY_NAMES.put("RU", "Russia");
        COUNTRY_NAMES.put("UA", "Ukraine");
        COUNTRY_NAMES.put("IN", "India");
        COUNTRY_NAMES.put("BR", "Brazil");
        COUNTRY_NAMES.put("NL", "Netherlands");
        COUNTRY_NAMES.put("CH", "Switzerland");
        COUNTRY_NAMES.put("SG", "Singapore");
        COUNTRY_NAMES.put("HK", "Hong Kong");
    }
    
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final PythonExecutionService pythonService;
    
    public PhishingDetectionService(PythonExecutionService pythonService) {
        this.pythonService = pythonService;
    }
    
    /**
     * Scan a URL for phishing detection using ML models.
     */
    public UrlScanResponse scanUrl(UrlScanRequest request) {
        try {
            String url = request.getUrl();
            logger.info("Scanning URL: {}", url);
            
            // Validate URL format
            if (!isValidUrl(url)) {
                return UrlScanResponse.error("Invalid URL format");
            }
            
            // Run heuristic check first (always)
            UrlScanResponse heuristicResult = heuristicUrlCheck(url);
            
            // Try Python ML script for detection
            try {
                Map<String, Object> mlResult = pythonService.detectUrl(url);
                
                if (mlResult != null && mlResult.containsKey("result")) {
                    String mlResultStatus = (String) mlResult.get("result");
                    Double mlConfidence = mlResult.get("confidence") != null ? 
                        ((Number) mlResult.get("confidence")).doubleValue() : 75.0;
                    
                    // If ML says phishing, trust it
                    if ("phishing".equals(mlResultStatus)) {
                        return UrlScanResponse.phishing(mlConfidence, 
                            (Map<String, Object>) mlResult.get("features"));
                    }
                    
                    // If ML says safe but heuristic says phishing, trust heuristic (it's more aggressive)
                    if ("phishing".equals(heuristicResult.getResult())) {
                        return heuristicResult;
                    }
                    
                    // Both say safe - return ML result
                    return UrlScanResponse.safe(mlConfidence, 
                        (Map<String, Object>) mlResult.get("features"));
                }
            } catch (Exception e) {
                logger.warn("Python ML check failed, using heuristic: {}", e.getMessage());
            }
            
            // Fallback to heuristic
            return heuristicResult;
            
        } catch (Exception e) {
            logger.error("Error scanning URL: {}", e.getMessage());
            return heuristicUrlCheck(request.getUrl());
        }
    }
    
    /**
     * Check SSL/TLS certificate validity.
     */
    public CertificateCheckResponse checkCertificate(CertificateCheckRequest request) {
        try {
            String domain = request.getDomain();
            Integer port = request.getPort();
            logger.info("Checking certificate for domain: {} on port: {}", domain, port);
            
            // Fetch certificate from the domain
            CertificateCheckResponse.CertificateDetails certDetails = fetchCertificateDetails(domain, port);
            
            // Use heuristic-based analysis for certificate (no ML API)
            boolean isValid = certDetails != null && 
                (certDetails.getIsValid() != null && certDetails.getIsValid());
            
            double confidence;
            String resultStatus;
            
            if (isValid) {
                // Check days until expiry for confidence calculation
                int daysUntilExpiry = certDetails.getDaysUntilExpiry() != null ? certDetails.getDaysUntilExpiry() : 0;
                
                if (daysUntilExpiry > 90) {
                    confidence = 85.0;
                } else if (daysUntilExpiry > 30) {
                    confidence = 75.0;
                } else if (daysUntilExpiry > 0) {
                    confidence = 60.0;
                } else {
                    confidence = 40.0;
                }
                resultStatus = "certificate-valid";
            } else {
                confidence = 70.0;
                resultStatus = "certificate-invalid";
            }
            
            if ("certificate-valid".equals(resultStatus)) {
                return CertificateCheckResponse.valid(confidence, certDetails);
            } else {
                return CertificateCheckResponse.invalid(confidence, certDetails);
            }
            
        } catch (Exception e) {
            logger.error("Error checking certificate: {}", e.getMessage());
            return CertificateCheckResponse.error("Error checking certificate: " + e.getMessage());
        }
    }
    
    /**
     * Lookup domain information for threat analysis.
     */
    public DomainLookupResponse lookupDomain(DomainLookupRequest request) {
        try {
            String domain = request.getDomain();
            logger.info("Looking up domain: {}", domain);
            
            // Clean the domain - remove protocol if present
            domain = cleanDomain(domain);
            
            // Try WHOIS lookup first
            WhoisResult whoisResult = performWhoisLookup(domain);
            
            if (whoisResult.isSuccessful()) {
                // Process WHOIS data and create detailed response
                return processWhoisResult(domain, whoisResult);
            } else {
                // Fallback to heuristic-based analysis
                logger.warn("WHOIS lookup failed, using heuristic: {}", whoisResult.getError());
                return heuristicDomainCheck(domain);
            }
            
        } catch (Exception e) {
            logger.error("Error looking up domain: {}", e.getMessage());
            return DomainLookupResponse.error("Error looking up domain: " + e.getMessage());
        }
    }
    
    /**
     * Clean domain string by removing protocol and path
     */
    private String cleanDomain(String input) {
        // Remove protocol
        if (input.startsWith("http://")) {
            input = input.substring(7);
        } else if (input.startsWith("https://")) {
            input = input.substring(8);
        }
        // Remove path
        int slashIndex = input.indexOf('/');
        if (slashIndex > 0) {
            input = input.substring(0, slashIndex);
        }
        // Remove port
        int colonIndex = input.indexOf(':');
        if (colonIndex > 0) {
            input = input.substring(0, colonIndex);
        }
        // Remove www. prefix for consistency
        if (input.startsWith("www.")) {
            input = input.substring(4);
        }
        return input.toLowerCase().trim();
    }
    
    /**
     * Perform WHOIS lookup for a domain
     */
    private WhoisResult performWhoisLookup(String domain) {
        StringBuilder response = new StringBuilder();
        
        try {
            // Extract TLD for appropriate WHOIS server
            String[] parts = domain.split("\\.");
            if (parts.length < 2) {
                return new WhoisResult(false, "Invalid domain format");
            }
            
            String tld = parts[parts.length - 1];
            String sld = parts.length > 1 ? parts[parts.length - 2] : "";
            
            // Try common WHOIS servers based on TLD
            String[] whoisServers = getWhoisServers(tld);
            
            for (String server : whoisServers) {
                try {
                    response.setLength(0);
                    response.append(queryWhoisServer(domain, server));
                    
                    if (response.length() > 100) {
                        return new WhoisResult(true, response.toString());
                    }
                } catch (Exception e) {
                    logger.debug("WHOIS server {} failed: {}", server, e.getMessage());
                }
            }
            
            // If all servers fail, return error
            return new WhoisResult(false, "Could not connect to any WHOIS server");
            
        } catch (Exception e) {
            return new WhoisResult(false, "WHOIS lookup error: " + e.getMessage());
        }
    }
    
    /**
     * Get appropriate WHOIS servers for a TLD
     */
    private String[] getWhoisServers(String tld) {
        // Common gTLDs and their WHOIS servers
        Map<String, String> whoisServers = new HashMap<>();
        whoisServers.put("com", "whois.verisign-grs.com");
        whoisServers.put("net", "whois.verisign-grs.com");
        whoisServers.put("org", "whois.pir.org");
        whoisServers.put("info", "whois.afilias.info");
        whoisServers.put("biz", "whois.neulevel.biz");
        whoisServers.put("io", "whois.nic.io");
        whoisServers.put("co", "whois.nic.co");
        whoisServers.put("ai", "whois.nic.ai");
        whoisServers.put("me", "whois.nic.me");
        whoisServers.put("tv", "whois.nic.tv");
        whoisServers.put("cc", "whois.nic.cc");
        whoisServers.put("xyz", "whois.nic.xyz");
        whoisServers.put("top", "whois.nic.top");
        whoisServers.put("site", "whois.nic.site");
        whoisServers.put("online", "whois.nic.online");
        whoisServers.put("store", "whois.nic.store");
        whoisServers.put("app", "whois.nic.google");
        whoisServers.put("dev", "whois.nic.google");
        
        String server = whoisServers.get(tld.toLowerCase());
        if (server != null) {
            return new String[]{server, "whois.iana.org"};
        }
        
        // Default fallback
        return new String[]{"whois.iana.org", "whois.verisign-grs.com"};
    }
    
    /**
     * Query a WHOIS server
     */
    private String queryWhoisServer(String domain, String server) throws Exception {
        StringBuilder response = new StringBuilder();
        
        try (Socket socket = new Socket(server, 43);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
            
            out.println(domain);
            
            String line;
            while ((line = in.readLine()) != null) {
                response.append(line).append("\n");
                
                // Limit response size
                if (response.length() > 10000) {
                    break;
                }
            }
        }
        
        return response.toString();
    }
    
    /**
     * Process WHOIS result and create detailed domain response
     */
    private DomainLookupResponse processWhoisResult(String domain, WhoisResult whoisResult) {
        String whoisData = whoisResult.getData();
        
        // Parse WHOIS data
        Map<String, String> parsedData = parseWhoisData(whoisData);
        
        // Extract key dates
        Date creationDate = parseDate(parsedData.get("creation date"));
        Date expiryDate = parseDate(parsedData.get("expiry date"));
        Date updatedDate = parseDate(parsedData.get("updated date"));
        
        // Calculate domain age
        int domainAgeDays = 0;
        if (creationDate != null) {
            domainAgeDays = (int) ((System.currentTimeMillis() - creationDate.getTime()) / (1000 * 60 * 60 * 24));
        }
        
        // Calculate days until expiry
        int daysUntilExpiry = 0;
        if (expiryDate != null) {
            daysUntilExpiry = (int) ((expiryDate.getTime() - System.currentTimeMillis()) / (1000 * 60 * 60 * 24));
        }
        
        // Extract registrar
        String registrar = parsedData.get("registrar");
        if (registrar == null) {
            registrar = parsedData.get("registrar url");
        }
        
        // Extract registrant info
        String registrantName = parsedData.get("registrant name");
        String registrantOrg = parsedData.get("registrant organization");
        String registrantCountry = parsedData.get("registrant country");
        String registrantState = parsedData.get("registrant state/province");
        String registrantCity = parsedData.get("registrant city");
        String registrantEmail = parsedData.get("registrant email");
        
        // Extract admin contact
        String adminName = parsedData.get("admin name");
        String adminOrg = parsedData.get("admin organization");
        String adminCountry = parsedData.get("admin country");
        String adminEmail = parsedData.get("admin email");
        
        // Extract tech contact
        String techName = parsedData.get("tech name");
        String techOrg = parsedData.get("tech organization");
        String techEmail = parsedData.get("tech email");
        
        // Extract name servers
        List<String> nameServers = extractNameServers(parsedData);
        
        // Check for privacy protection
        boolean isPrivacyProtected = isPrivacyProtection(whoisData, registrantEmail);
        
        // Check DNSSEC
        String dnssec = parsedData.get("dnssec");
        boolean hasDnssec = dnssec != null && !dnssec.isEmpty() && !dnssec.equals("unsigned");
        
        // Calculate risk score
        int score = calculateRiskScore(domain, domainAgeDays, registrar, registrantCountry, 
                                        isPrivacyProtected, nameServers.size(), daysUntilExpiry);
        

        boolean isSuspicious = score >= 2;
        double confidence = Math.min(70.0 + score * 8, 95.0);
        
        // Step 2: ML Domain Model Integration
        try {
            Map<String, Object> domainFeatures = new HashMap<>();
            domainFeatures.put("domain_age_days", domainAgeDays);
            domainFeatures.put("is_new_domain", (domainAgeDays >= 0 && domainAgeDays < 90));
            domainFeatures.put("registrar_known", isKnownRegistrar(registrar));
            domainFeatures.put("registrant_country", registrantCountry);
            domainFeatures.put("is_high_risk_country", registrantCountry != null && HIGH_RISK_COUNTRIES.contains(registrantCountry.toUpperCase()));
            domainFeatures.put("privacy_protected", isPrivacyProtected);

            domainFeatures.put("nameserver_count", nameServers.size());
            domainFeatures.put("days_until_expiry", daysUntilExpiry);
            domainFeatures.put("risk_score", score);
            domainFeatures.put("domain", domain);
            
            Map<String, Object> mlResult = pythonService.detectDomain(domainFeatures);
            if (mlResult != null && "phishing".equals(mlResult.get("result"))) {
                isSuspicious = true;
                Double mlConfidence = mlResult.get("confidence") != null ? ((Number) mlResult.get("confidence")).doubleValue() : 80.0;
                confidence = Math.max(confidence, mlConfidence);
                logger.info("ML Domain model flagged {} as phishing (conf: {})", domain, mlConfidence);
            } else {
                logger.info("ML Domain model safe for {}", domain);
            }
        } catch (Exception e) {
            logger.warn("ML Domain check failed for {}: {}", domain, e.getMessage());
        }
        
        // Step 3: Certificate (CRT) Check Integration
        boolean certValid = true;
        double certConfidence = 100.0;
        String certStatus = "unknown";
        try {
            CertificateCheckRequest certRequest = new CertificateCheckRequest();
            certRequest.setDomain(domain);
            CertificateCheckResponse certResponse = checkCertificate(certRequest);


            certStatus = certResponse.getResult();
            if ("certificate-invalid".equals(certStatus) || 
                (certResponse.getDetails() != null && Boolean.FALSE.equals(certResponse.getDetails().getIsValid()))) {
                isSuspicious = true;
                confidence = Math.max(confidence, 85.0);
                certValid = false;
                certConfidence = certResponse.getConfidence() != null ? certResponse.getConfidence() : 70.0;
                logger.info("Invalid cert flagged {} as suspicious (conf: {})", domain, confidence);
            } else {
                logger.info("Valid cert for {}", domain);
            }
        } catch (Exception e) {
            logger.warn("Cert check failed for {} (no HTTPS?): {}", domain, e.getMessage());
            certStatus = "no-cert";
            // No HTTPS cert = highly suspicious for phishing
            isSuspicious = true;
            confidence = Math.max(confidence, 85.0);
            certValid = false;
            certConfidence = 0.0;
            logger.info("No HTTPS cert → phishing flag for {}", domain);
        }

        
// Calculate country risk BEFORE ML/Cert
        String countryCode = registrantCountry != null ? registrantCountry.toUpperCase() : null;
        String countryName = countryCode != null ? COUNTRY_NAMES.getOrDefault(countryCode, countryCode) : null;
        boolean isHighRiskCountry = countryCode != null && HIGH_RISK_COUNTRIES.contains(countryCode);

        
        // Build domain details
        double mlConfidence = 50.0; // Default neutral
        DomainLookupResponse.DomainDetails details = DomainLookupResponse.DomainDetails.builder()
            .domain(domain)
            .domainName(extractDomainName(domain))
            .tld(extractTld(domain))
            .domainAgeDays(domainAgeDays)
            .isNewDomain(domainAgeDays >= 0 && domainAgeDays < 90)
            .daysUntilExpiry(daysUntilExpiry)
            .registrar(registrar)
            .registrarUrl(parsedData.get("registrar url"))
            .isKnownRegistrar(isKnownRegistrar(registrar))
            .country(countryCode)
            .countryName(countryName)
            .isHighRiskCountry(isHighRiskCountry)
            .hasPrivacyProtection(isPrivacyProtected)
            .nameserverCount(nameServers.size())
            .nameServers(nameServers)
            .hasDnssec(hasDnssec)
            .dnssecStatus(dnssec)
            .isParked(isParkedDomain(whoisData))
            .isForSale(isForSaleDomain(whoisData))
            .domainStatus(parsedData.get("status"))
            .creationDate(formatDate(creationDate))
            .expiryDate(formatDate(expiryDate))
            .updatedDate(formatDate(updatedDate))
            .build();


        
        // Build ownership info
        DomainLookupResponse.OwnershipInfo ownership = DomainLookupResponse.OwnershipInfo.builder()
            .registrantName(registrantName)
            .registrantOrganization(registrantOrg)
            .registrantCountry(countryName)
            .registrantCountryCode(countryCode)
            .registrantState(registrantState)
            .registrantCity(registrantCity)
            .registrantEmail(maskEmail(registrantEmail))
            .adminContactName(adminName)
            .adminContactOrg(adminOrg)
            .adminContactCountry(adminCountry)
            .adminContactEmail(maskEmail(adminEmail))
            .techContactName(techName)
            .techContactOrg(techOrg)
            .techContactEmail(maskEmail(techEmail))
            .isPrivacyProtected(isPrivacyProtected)
            .proxyService(isPrivacyProtected ? "Domain Privacy Service" : null)
            .build();
        
        if (isSuspicious) {
            return DomainLookupResponse.suspicious(confidence, details, ownership);
        } else {
            return DomainLookupResponse.valid(confidence, details, ownership);
        }
    }
    
    /**
     * Parse WHOIS data into key-value pairs
     */
    private Map<String, String> parseWhoisData(String whoisData) {
        Map<String, String> result = new HashMap<>();
        
        if (whoisData == null || whoisData.isEmpty()) {
            return result;
        }
        
        Pattern pattern = Pattern.compile("^([\\w\\s\\-]+):\\s*(.*)$", Pattern.CASE_INSENSITIVE);
        String[] lines = whoisData.split("\n");
        
        for (String line : lines) {
            Matcher matcher = pattern.matcher(line.trim());
            if (matcher.matches()) {
                String key = matcher.group(1).trim().toLowerCase();
                String value = matcher.group(2).trim();
                
                // Handle multi-line values
                if (result.containsKey(key)) {
                    result.put(key, result.get(key) + "; " + value);
                } else {
                    result.put(key, value);
                }
            }
        }
        
        return result;
    }
    
    /**
     * Extract name servers from parsed WHOIS data
     */
    private List<String> extractNameServers(Map<String, String> parsedData) {
        List<String> nameServers = new ArrayList<>();
        
        // Check various possible field names
        String[] nsFields = {"name server", "nserver", "nameserver", "name servers"};
        
        for (String field : nsFields) {
            String value = parsedData.get(field);
            if (value != null && !value.isEmpty()) {
                // Split by semicolon or newline
                String[] servers = value.split("[;\\n]");
                for (String server : servers) {
                    server = server.trim().toLowerCase();
                    if (!server.isEmpty() && !nameServers.contains(server)) {
                        nameServers.add(server);
                    }
                }
            }
        }
        
        return nameServers;
    }
    
    /**
     * Check if domain has privacy protection
     */
    private boolean isPrivacyProtection(String whoisData, String email) {
        if (email == null) return false;
        
        // Common privacy protection patterns
        String[] privacyPatterns = {"privacy", "proxy", "redacted", "contact", "confidential", 
                                      "domainsbyproxy", "whoisguard", "namecheap", "heroic"};
        
        String lowerData = whoisData.toLowerCase();
        String lowerEmail = email.toLowerCase();
        
        for (String pattern : privacyPatterns) {
            if (lowerData.contains(pattern) || lowerEmail.contains(pattern)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check if domain appears to be parked
     */
    private boolean isParkedDomain(String whoisData) {
        String[] parkedIndicators = {"parked", "for sale", "domain parking", "this domain may be for sale"};
        String lowerData = whoisData.toLowerCase();
        
        for (String indicator : parkedIndicators) {
            if (lowerData.contains(indicator)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Check if domain appears to be for sale
     */
    private boolean isForSaleDomain(String whoisData) {
        String[] saleIndicators = {"for sale", "buy this domain", "domain for sale", "sale pending"};
        String lowerData = whoisData.toLowerCase();
        
        for (String indicator : saleIndicators) {
            if (lowerData.contains(indicator)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Calculate risk score based on domain characteristics
     */
    private int calculateRiskScore(String domain, int domainAgeDays, String registrar, 
                                     String country, boolean isPrivacyProtected, 
                                     int nameserverCount, int daysUntilExpiry) {
        int score = 0;
        
        // New domain (less than 90 days) is suspicious
        if (domainAgeDays > 0 && domainAgeDays < 30) score += 3;
        else if (domainAgeDays >= 30 && domainAgeDays < 90) score += 2;
        
        // Very new domains (< 7 days) are highly suspicious
        if (domainAgeDays < 7) score += 2;
        
        // Unknown registrar
        if (registrar == null || registrar.isEmpty()) score += 1;
        
        // High-risk country
        if (country != null && HIGH_RISK_COUNTRIES.contains(country.toUpperCase())) {
            score += 2;
        }
        
        // Privacy protection on new domain - suspicious
        if (isPrivacyProtected && domainAgeDays < 180) score += 2;
        
        // Very few name servers
        if (nameserverCount < 2) score += 1;
        
        // Domain expiring soon
        if (daysUntilExpiry > 0 && daysUntilExpiry < 30) score += 1;
        
        // Suspicious TLDs
        String[] suspiciousTlds = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "pw"};
        for (String tld : suspiciousTlds) {
            if (domain.toLowerCase().endsWith("." + tld)) {
                score += 2;
                break;
            }
        }
        
        // Domain with numbers (suspicious patterns)
        if (domain.matches(".*\\d{4,}.*")) score += 1;
        
        return score;
    }
    
    /**
     * Check if registrar is known/legitimate
     */
    private boolean isKnownRegistrar(String registrar) {
        if (registrar == null || registrar.isEmpty()) return false;
        
        String lowerRegistrar = registrar.toLowerCase();
        for (String known : KNOWN_REGISTRARS) {
            if (lowerRegistrar.contains(known.toLowerCase())) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Extract simple domain name without TLD
     */
    private String extractDomainName(String domain) {
        String[] parts = domain.split("\\.");
        if (parts.length >= 2) {
            return parts[parts.length - 2];
        }
        return domain;
    }
    
    /**
     * Extract TLD from domain
     */
    private String extractTld(String domain) {
        String[] parts = domain.split("\\.");
        if (parts.length >= 2) {
            return parts[parts.length - 1];
        }
        return "";
    }
    
    /**
     * Mask email address for privacy
     */
    private String maskEmail(String email) {
        if (email == null || email.isEmpty()) return null;
        
        int atIndex = email.indexOf('@');
        if (atIndex > 0) {
            String prefix = email.substring(0, Math.min(2, atIndex));
            return prefix + "***@***" + email.substring(email.indexOf('@'));
        }
        return email;
    }
    
    /**
     * Parse date from various formats
     */
    private Date parseDate(String dateStr) {
        if (dateStr == null || dateStr.isEmpty()) return null;
        
        String[] formats = {
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            "yyyy-MM-dd HH:mm:ss",
            "yyyy-MM-dd",
            "dd-MMM-yyyy",
            "MMM dd, yyyy",
            "yyyy/MM/dd"
        };
        
        for (String format : formats) {
            try {
                SimpleDateFormat sdf = new SimpleDateFormat(format);
                return sdf.parse(dateStr);
            } catch (Exception e) {
                // Try next format
            }
        }
        return null;
    }
    
    /**
     * Format date to string
     */
    private String formatDate(Date date) {
        if (date == null) return null;
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        return sdf.format(date);
    }
    
    /**
     * Inner class to hold WHOIS query result
     */
    private static class WhoisResult {
        private final boolean successful;
        private final String data;
        private final String error;
        
        public WhoisResult(boolean successful, String data) {
            this.successful = successful;
            this.data = data;
            this.error = null;
        }
        
        public boolean isSuccessful() {
            return successful;
        }
        
        public String getData() {
            return data;
        }
        
        public String getError() {
            return error;
        }
    }
    
    // Helper Methods
    
    @SuppressWarnings("deprecation")
    private boolean isValidUrl(String url) {
        try {
            new java.net.URL(url).toURI();
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    private UrlScanResponse heuristicUrlCheck(String url) {
        int score = 0;
        
        // Length check - phishing URLs are often longer
        if (url.length() > 30) score += 1;
        if (url.length() > 50) score += 1;
        if (url.length() > 75) score += 2;
        if (url.length() > 100) score += 2;
        
        // Contains @ symbol (very common in phishing - used to confuse users)
        if (url.contains("@")) score += 3;
        
        // NO HTTPS - MAJOR RED FLAG for .com, .net, .org domains
        if (!url.startsWith("https://")) {
            score += 2;
            // Extra penalty for commercial domains without HTTPS
            if (url.contains(".com") || url.contains(".net") || url.contains(".org")) {
                score += 1;
            }
        }
        
        // Suspicious TLDs (common in free phishing domains)
        String[] suspiciousTlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click", ".pw", ".cc", ".shop", ".site", ".online", ".store"};
        for (String tld : suspiciousTlds) {
            if (url.toLowerCase().endsWith(tld) || url.toLowerCase().contains(tld)) {
                score += 3;
                break;
            }
        }
        
        // Suspicious domain patterns (commonly used in fake investment/trading sites)
        String[] suspiciousDomains = {"alp-trade", "trade", "forex", "crypto", "invest", "profit", "million", "binary", "btc", "bitcoin", "eth", "wallet", "mining", "exchange"};
        String lowerUrl = url.toLowerCase();
        for (String domain : suspiciousDomains) {
            if (lowerUrl.contains(domain)) {
                score += 2;
                break;
            }
        }
        
        // IP address in URL (suspicious)
        if (url.matches(".*https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*")) {
            score += 3;
        }
        
        // Multiple dots in domain (subdomain tricks)
        String[] parts = url.split("/");
        if (parts.length > 0) {
            String domainPart = parts[0];
            int dotCount = domainPart.split("\\.").length - 1;
            if (dotCount > 2) score += 1;
            if (dotCount > 3) score += 2;
        }
        
        // Suspicious keywords in URL
        String[] suspiciousKeywords = {"login", "signin", "verify", "secure", "account", "update", "confirm", "bank", "paypal", "amazon", "apple", "microsoft", "google", "facebook", "netflix", "ebay", "wallet", "password", "credential", "register", "signup", "free", "bonus", "win", "winner", "prize", "claim"};
        for (String kw : suspiciousKeywords) {
            if (lowerUrl.contains(kw)) {
                score += 1;
            }
        }
        
        // Encoded characters (used to hide malicious content)
        if (url.contains("%20") || url.contains("%3A") || url.contains("%2F")) {
            score += 1;
        }
        
        // Double extensions (e.g., .pdf.exe)
        if (url.matches(".*\\.\\w+\\.\\w+$")) {
            score += 2;
        }
        
        // Domain age check via domain length (short domains with common words are suspicious)
        try {
            java.net.URL parsedUrl = new java.net.URL(url);
            String host = parsedUrl.getHost();
            // Remove www. prefix
            if (host.startsWith("www.")) host = host.substring(4);
            // Check if domain name is short and contains suspicious words
            String[] hostParts = host.split("\\.");
            if (hostParts.length > 0) {
                String domainName = hostParts[0];
                if (domainName.length() <= 8 && (lowerUrl.contains("trade") || lowerUrl.contains("invest") || lowerUrl.contains("profit"))) {
                    score += 2;
                }
            }
        } catch (Exception e) {
            // Ignore parsing errors
        }
        
        // Lower threshold to catch more phishing (was 3, now 2)
        boolean isPhishing = score >= 2;
        double confidence = Math.min(60.0 + score * 8, 95.0);
        
        logger.info("Heuristic URL check - Score: {}, URL: {}", score, url);
        
        return isPhishing ? 
            UrlScanResponse.phishing(confidence, Map.of("score", score)) : 
            UrlScanResponse.safe(confidence, Map.of("score", score));
    }
    
    private CertificateCheckResponse.CertificateDetails fetchCertificateDetails(String hostname, int port) {
        try {
            // Create a socket connection to get certificate info
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            Socket socket = factory.createSocket(hostname, port);
            
            if (socket instanceof SSLSocket) {
                SSLSocket sslSocket = (SSLSocket) socket;
                sslSocket.startHandshake();
                
                javax.net.ssl.SSLSession sslSession = sslSocket.getSession();
                java.security.cert.Certificate[] certs = sslSession.getPeerCertificates();
                
                if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                    X509Certificate cert = (X509Certificate) certs[0];
                    
                    return CertificateCheckResponse.CertificateDetails.builder()
                        .isValid(true)
                        .subject(cert.getSubjectX500Principal().getName())
                        .issuer(cert.getIssuerX500Principal().getName())
                        .keySize(getKeySize(cert))
                        .daysUntilExpiry(calculateDaysUntilExpiry(cert))
                        .hasChain(certs.length > 1)
                        .sanCount(getSANCount(cert))
                        .hasWildcard(hostname.startsWith("*."))
                        .signatureAlgorithm(cert.getSigAlgName())
                        .build();
                }
            }
            socket.close();
            
        } catch (Exception e) {
            logger.warn("Could not fetch certificate: {}", e.getMessage());
        }
        
        return CertificateCheckResponse.CertificateDetails.builder()
            .isValid(false)
            .build();
    }
    
    private int getKeySize(X509Certificate cert) {
        try {
            java.security.PublicKey key = cert.getPublicKey();
            return key.getEncoded().length * 8;
        } catch (Exception e) {
            return 2048; // Default
        }
    }
    
    private int calculateDaysUntilExpiry(X509Certificate cert) {
        try {
            Date notAfter = cert.getNotAfter();
            long diff = notAfter.getTime() - System.currentTimeMillis();
            return (int) (diff / (1000 * 60 * 60 * 24));
        } catch (Exception e) {
            return -1;
        }
    }
    
    private int getSANCount(X509Certificate cert) {
        try {
            java.util.Collection<?> sanList = cert.getSubjectAlternativeNames();
            return sanList != null ? sanList.size() : 0;
        } catch (Exception e) {
            return 0;
        }
    }
    
    private Map<String, Object> certDetailsToMap(CertificateCheckResponse.CertificateDetails details) {
        Map<String, Object> map = new HashMap<>();
        if (details.getIsValid() != null) map.put("is_valid", details.getIsValid());
        if (details.getDaysUntilExpiry() != null) map.put("days_until_expiry", details.getDaysUntilExpiry());
        if (details.getKeySize() != null) map.put("key_size", details.getKeySize());
        if (details.getHasChain() != null) map.put("has_chain", details.getHasChain());
        if (details.getIssuer() != null) map.put("issuer", details.getIssuer());
        if (details.getSubject() != null) map.put("subject", details.getSubject());
        return map;
    }
    
    private DomainLookupResponse.DomainDetails buildDomainDetails(Map<String, Object> detailsMap) {
        
        if (detailsMap == null) {
            return DomainLookupResponse.DomainDetails.builder().build();
        }
        
        return DomainLookupResponse.DomainDetails.builder()
            .domainAgeDays(getIntValue(detailsMap, "domain_age_days"))
            .isNewDomain(getIntValue(detailsMap, "domain_age_days") >= 0 && 
                        getIntValue(detailsMap, "domain_age_days") < 90)
            .daysUntilExpiry(getIntValue(detailsMap, "days_until_expiry"))
            .isHighRiskCountry(getBoolValue(detailsMap, "is_high_risk_country"))
            .hasDnssec(getBoolValue(detailsMap, "has_dnssec"))
            .nameserverCount(getIntValue(detailsMap, "nameserver_count"))
            .build();
    }
    
    private int getIntValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        return 0;
    }
    
    private boolean getBoolValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        return false;
    }
    
    private DomainLookupResponse heuristicDomainCheck(String domain) {
        int score = 0;
        
        // Check domain length
        if (domain.length() > 20) score += 1;
        if (domain.length() > 30) score += 1;
        
        // Check for numbers
        if (domain.matches(".*\\d{3,}.*")) score += 1;
        
        // Suspicious TLDs
        String[] suspiciousTlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"};
        for (String tld : suspiciousTlds) {
            if (domain.toLowerCase().endsWith(tld)) {
                score += 2;
                break;
            }
        }
        
        boolean isSuspicious = score >= 2;
        double confidence = Math.min(70.0 + score * 10, 95.0);
        
        DomainLookupResponse.DomainDetails details = 
            DomainLookupResponse.DomainDetails.builder()
                .domain(domain)
                .isNewDomain(score >= 2)
                .build();
        
        return isSuspicious ? 
            DomainLookupResponse.suspicious(confidence, details) : 
            DomainLookupResponse.valid(confidence, details);
    }
}
