package com.phishguard.controller;

import com.phishguard.dto.DomainLookupRequest;
import com.phishguard.dto.DomainLookupResponse;
import com.phishguard.entity.UrlHistory;
import com.phishguard.entity.User;
import com.phishguard.repository.UrlHistoryRepository;
import com.phishguard.repository.UserRepository;
import com.phishguard.service.PhishingDetectionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import java.time.LocalDateTime;

/**
 * REST Controller for domain lookup operations.
 */
@RestController
@RequestMapping("/api/domain")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
public class DomainController {
    
    private static final Logger logger = LoggerFactory.getLogger(DomainController.class);
    
    private final PhishingDetectionService phishingDetectionService;
    private final UrlHistoryRepository urlHistoryRepository;
    private final UserRepository userRepository;

    /**
     * Lookup domain information for threat analysis.
     * POST /api/domain/lookup
     */
    @PostMapping("/lookup")
    public ResponseEntity<DomainLookupResponse> lookupDomain(
            @Valid @RequestBody DomainLookupRequest request) {
        logger.info("Received domain lookup request for: {}", request.getDomain());
        DomainLookupResponse response = phishingDetectionService.lookupDomain(request);
        
        // Save to history if authenticated
        // Domain is suspicious if result is 'domain-suspicious' (not just high confidence)
        boolean isPhishing = "domain-suspicious".equals(response.getResult());
        saveHistory(request.getDomain(), response.getConfidence(), 
                   isPhishing,
                   response.getMessage());
        
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
    
    private void saveHistory(String url, Double score, boolean isPhishing, String details) {
        try {
            var authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.getName() != null) {
                String email = authentication.getName();
                var userOpt = userRepository.findByEmail(email);
                if (userOpt.isPresent()) {
                    User user = userOpt.get();
                    UrlHistory history = new UrlHistory();
                    history.setUser(user);
                    history.setUrl(url);
                    history.setPhishingScore(score);
                    history.setIsPhishing(isPhishing);
                    history.setDetails(details);
                    history.setScannedAt(LocalDateTime.now());
                    urlHistoryRepository.save(history);
                    logger.info("Saved domain history for user: {}", email);
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to save history: {}", e.getMessage());
        }
    }
}
