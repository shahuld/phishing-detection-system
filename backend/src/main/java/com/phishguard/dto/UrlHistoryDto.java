package com.phishguard.dto;

import lombok.Data;
import lombok.Setter;
import java.time.LocalDateTime;

@Data
public class UrlHistoryDto {
    private Long id;
    private String url;
    private Double phishingScore;
    @Setter
    private boolean isPhishing;
    private LocalDateTime scannedAt;
    private String details;

    public void setIsPhishing(boolean isPhishing) {
        this.isPhishing = isPhishing;
    }
}
