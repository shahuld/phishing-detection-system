package com.phishguard.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Request DTO for URL scanning.
 */
@Data
public class UrlScanRequest {
    
    @NotBlank(message = "URL is required")
    private String url;
    
    private Boolean includeFeatures = false;
}
