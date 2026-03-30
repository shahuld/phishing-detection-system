package com.phishguard;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Main Spring Boot Application for PhishGuard Backend.
 * Provides REST API endpoints for phishing detection services.
 * 
 * Services:
 * - URL Scanner: Detect phishing URLs
 * - Certificate Check: Verify SSL/TLS certificates
 * - Domain Lookup: Research domain registration details
 */
@SpringBootApplication
public class PhishGuardApplication {

    public static void main(String[] args) {
        SpringApplication.run(PhishGuardApplication.class, args);
    }

    /**
     * CORS configuration to allow frontend requests from different origins.
     */
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**")
                        .allowedOrigins("*")
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                        .allowedHeaders("*")
                        .maxAge(3600);
            }
        };
    }
}
