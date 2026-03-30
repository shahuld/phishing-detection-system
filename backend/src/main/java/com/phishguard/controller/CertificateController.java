package com.phishguard.controller;

import com.phishguard.dto.CertificateCheckRequest;
import com.phishguard.dto.CertificateCheckResponse;
import com.phishguard.service.PhishingDetectionService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST Controller for certificate checking operations.
 */
@RestController
@RequestMapping("/api/certificate")
@CrossOrigin(origins = "*")
public class CertificateController {
    
    private static final Logger logger = LoggerFactory.getLogger(CertificateController.class);
    private final PhishingDetectionService phishingDetectionService;
    
    public CertificateController(PhishingDetectionService phishingDetectionService) {
        this.phishingDetectionService = phishingDetectionService;
    }
    
    /**
     * Check SSL/TLS certificate validity.
     * POST /api/certificate/check
     */
    @PostMapping("/check")
    public ResponseEntity<CertificateCheckResponse> checkCertificate(
            @Valid @RequestBody CertificateCheckRequest request) {
        logger.info("Received certificate check request for: {}", request.getDomain());
        CertificateCheckResponse response = phishingDetectionService.checkCertificate(request);
        return ResponseEntity.ok(response);
    }
    
    /**
     * Health check endpoint.
     * GET /api/certificate/health
     */
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("Certificate Check Service is running");
    }
}
