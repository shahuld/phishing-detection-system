package com.phishguard.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Request DTO for domain lookup.
 */
@Data
public class DomainLookupRequest {
    
    @NotBlank(message = "Domain is required")
    private String domain;
    
    private Boolean includeDetails = true;
}
