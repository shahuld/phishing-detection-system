package com.phishguard.controller;

import com.phishguard.dto.DomainLookupRequest;
import com.phishguard.dto.DomainLookupResponse;
import com.phishguard.service.PhishingDetectionService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST Controller for domain lookup operations.
 */
@RestController
@RequestMapping("/api/domain")
@CrossOrigin(origins = "*")
public class DomainController {
    
    private static final Logger logger = LoggerFactory.getLogger(DomainController.class);
    private final PhishingDetectionService phishingDetectionService;
    
    public DomainController(PhishingDetectionService phishingDetectionService) {
        this.phishingDetectionService = phishingDetectionService;
    }
    
    /**
     * Lookup domain information for threat analysis.
     * POST /api/domain/lookup
     */
    @PostMapping("/lookup")
    public ResponseEntity<DomainLookupResponse> lookupDomain(
            @Valid @RequestBody DomainLookupRequest request) {
        logger.info("Received domain lookup request for: {}", request.getDomain());
        DomainLookupResponse response = phishingDetectionService.lookupDomain(request);
        return ResponseEntity.ok(response);
    }
    
    /**
     * Health check endpoint.
     * GET /api/domain/health
     */
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("Domain Lookup Service is running");
    }
}
