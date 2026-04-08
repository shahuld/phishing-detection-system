package com.phishguard.controller;

import com.phishguard.dto.UrlScanRequest;
import com.phishguard.dto.UrlScanResponse;
import com.phishguard.service.PhishingDetectionService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.phishguard.entity.UrlHistory;
import com.phishguard.entity.User;
import com.phishguard.repository.UrlHistoryRepository;
import com.phishguard.repository.UserRepository;
import org.springframework.security.core.context.SecurityContextHolder;
import lombok.RequiredArgsConstructor;
import java.time.LocalDateTime;

/**
 * REST Controller for URL scanning operations.
 */
@RestController
@RequestMapping("/api/url")
@CrossOrigin(origins = "*")
public class URLController {
    
    private static final Logger logger = LoggerFactory.getLogger(URLController.class);
    
    private final PhishingDetectionService phishingDetectionService;
    private final UrlHistoryRepository urlHistoryRepository;
    private final UserRepository userRepository;

    public URLController(PhishingDetectionService phishingDetectionService,
                        UrlHistoryRepository urlHistoryRepository,
                        UserRepository userRepository) {
        this.phishingDetectionService = phishingDetectionService;
        this.urlHistoryRepository = urlHistoryRepository;
        this.userRepository = userRepository;
    }
    
    /**
     * Scan a URL for phishing detection.
     * POST /api/url/scan
     */
    @PostMapping("/scan")
    public ResponseEntity<UrlScanResponse> scanUrl(@Valid @RequestBody UrlScanRequest request) {
        logger.info("Received URL scan request for: {}", request.getUrl());
        UrlScanResponse response = phishingDetectionService.scanUrl(request);
        
        // Save to user history if authenticated
        try {
            var authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.getName() != null) {
                String email = authentication.getName();
                var userOpt = userRepository.findByEmail(email);
                if (userOpt.isPresent()) {
                    User user = userOpt.get();
                    UrlHistory history = new UrlHistory();
                    history.setUser(user);
                    history.setUrl(request.getUrl());
                    history.setPhishingScore(response.getConfidence());
                    history.setIsPhishing("phishing".equals(response.getResult()));
                    history.setDetails(response.getMessage());
                    history.setScannedAt(LocalDateTime.now());
                    urlHistoryRepository.save(history);
                    logger.info("Saved URL history for user: {}", email);
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to save history: {}", e.getMessage());
        }
        
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
