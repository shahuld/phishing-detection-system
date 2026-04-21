package com.phishguard.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

/**
 * Request DTO for certificate checking.
 */
@Data
public class CertificateCheckRequest {
    
    @NotBlank(message = "URL is required")
    @Pattern(regexp = "^(https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\\.?[a-zA-Z]{2,}|[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}(?::[0-9]+)?|localhost)(/.*)?$", 
              message = "Invalid URL or domain")
    private String url;

    private String hostname;
    
    private Integer port = 443;
}
