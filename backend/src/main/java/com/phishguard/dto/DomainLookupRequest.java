package com.phishguard.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

/**
 * Request DTO for domain lookup.
 */
@Data
public class DomainLookupRequest {
    
    @NotBlank(message = "Domain/URL is required")
@Pattern(regexp = "^(?:https?://)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\\.?[a-zA-Z]{2,}|[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}(?::[0-9]+)?|localhost)$", message = "Invalid domain, URL, IP, or localhost")
    private String domain;
    
    private Boolean includeDetails = true;
}

