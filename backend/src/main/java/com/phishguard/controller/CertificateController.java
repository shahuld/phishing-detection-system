package com.phishguard.controller;

import com.phishguard.dto.CertificateCheckRequest;
import com.phishguard.dto.CertificateCheckResponse;
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
 * REST Controller for certificate checking operations.
 */
@RestController
@RequestMapping("/api/certificate")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
public class CertificateController {
    
    private static final Logger logger = LoggerFactory.getLogger(CertificateController.class);
    
    private final PhishingDetectionService phishingDetectionService;
    private final UrlHistoryRepository urlHistoryRepository;
    private final UserRepository userRepository;

    /**
     * Check SSL/TLS certificate validity.
     * POST /api/certificate/check
     */
    @PostMapping("/check")
    public ResponseEntity<CertificateCheckResponse> checkCertificate(
            @Valid @RequestBody CertificateCheckRequest request) {
        logger.info("Received certificate check request for: {}", request.getUrl());
        CertificateCheckResponse response = phishingDetectionService.checkCertificate(request);
        
        // Save to history if authenticated - use the original URL for history
        boolean isPhishing = !response.getDetails().isValid() || "invalid".equals(response.getResult());
        saveHistory(request.getUrl(), response.getConfidence(), isPhishing, response.getMessage());
        
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
                    logger.info("Saved certificate history for user: {}", email);
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to save history: {}", e.getMessage());
        }
    }
}
