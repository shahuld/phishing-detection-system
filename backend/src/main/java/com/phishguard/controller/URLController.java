package com.phishguard.controller;

import com.phishguard.dto.UrlScanRequest;
import com.phishguard.dto.UrlScanResponse;
import com.phishguard.service.PhishingDetectionService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST Controller for URL scanning operations.
 */
@RestController
@RequestMapping("/api/url")
@CrossOrigin(origins = "*")
public class URLController {
    
    private static final Logger logger = LoggerFactory.getLogger(URLController.class);
    private final PhishingDetectionService phishingDetectionService;
    
    public URLController(PhishingDetectionService phishingDetectionService) {
        this.phishingDetectionService = phishingDetectionService;
    }
    
    /**
     * Scan a URL for phishing detection.
     * POST /api/url/scan
     */
    @PostMapping("/scan")
    public ResponseEntity<UrlScanResponse> scanUrl(@Valid @RequestBody UrlScanRequest request) {
        logger.info("Received URL scan request for: {}", request.getUrl());
        UrlScanResponse response = phishingDetectionService.scanUrl(request);
        return ResponseEntity.ok(response);
    }
    
    /**
     * Health check endpoint.
     * GET /api/url/health
     */
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("URL Scanner Service is running");
    }
}
