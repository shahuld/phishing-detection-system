package com.phishguard.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Request DTO for certificate checking.
 */
@Data
public class CertificateCheckRequest {
    
    @NotBlank(message = "Domain is required")
    private String domain;
    
    private String hostname;
    
    private Integer port = 443;
}
