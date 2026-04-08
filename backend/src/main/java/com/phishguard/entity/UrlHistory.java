package com.phishguard.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Setter;
import java.time.LocalDateTime;

@Entity
@Table(name = "url_history")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UrlHistory {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    
    @Column(nullable = false, length = 2048)
    private String url;
    
    @Column(nullable = false)
    private Double phishingScore;
    
    @Column(nullable = false)
    @Setter
    private boolean isPhishing;
    
    @Column(name = "scanned_at", nullable = false)
    private LocalDateTime scannedAt = LocalDateTime.now();
    
    @Column(length = 500)
    private String details;

    public void setIsPhishing(boolean isPhishing) {
        this.isPhishing = isPhishing;
    }
}
