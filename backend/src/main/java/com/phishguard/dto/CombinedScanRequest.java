package com.phishguard.dto;

import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * Request DTO for combined phishing scan across all three services.
 * Extends UrlScanRequest since it uses the same URL input.
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class CombinedScanRequest extends UrlScanRequest {
    // Inherits url and includeFeatures from UrlScanRequest
}

