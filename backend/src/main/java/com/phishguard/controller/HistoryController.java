package com.phishguard.controller;

import com.phishguard.dto.UrlHistoryDto;
import com.phishguard.entity.UrlHistory;
import com.phishguard.entity.User;
import com.phishguard.repository.UrlHistoryRepository;
import com.phishguard.repository.UserRepository;
import com.phishguard.service.UserService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.stream.Collectors;

/**
 * REST Controller for user URL history.
 */
@RestController
@RequestMapping("/api/history")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
public class HistoryController {
    
    private static final Logger logger = LoggerFactory.getLogger(HistoryController.class);
    private final UrlHistoryRepository urlHistoryRepository;
    private final UserRepository userRepository;
    
    @GetMapping
    public List<UrlHistoryDto> getUserHistory() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        logger.info("Fetching history for user: {}", email);
        
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        return urlHistoryRepository.findByUserIdOrderByScannedAtDesc(user.getId())
                .stream()
                .map(this::toDto)
                .collect(Collectors.toList());
    }
    
    private UrlHistoryDto toDto(UrlHistory history) {
        UrlHistoryDto dto = new UrlHistoryDto();
        dto.setId(history.getId());
        dto.setUrl(history.getUrl());
        dto.setPhishingScore(history.getPhishingScore());
        dto.setIsPhishing(history.isPhishing());
        dto.setScannedAt(history.getScannedAt());
        dto.setDetails(history.getDetails());
        return dto;
    }
}
