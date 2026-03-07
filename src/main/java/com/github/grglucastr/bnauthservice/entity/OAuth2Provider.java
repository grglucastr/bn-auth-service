package com.github.grglucastr.bnauthservice.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "oauth2_providers",
        uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "provider"}))
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2Provider {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, length = 50)
    private String provider; // "google", "github", etc

    @Column(name = "provider_user_id", nullable = false)
    private String providerUserId; //User's ID from the provider

    @Column(name = "provider_email")
    private String providerEmail;

    @Column(name = "provider_name")
    private String providerName;

    @Column(name = "provider_picture")
    private String providerPicture;

    @Column(name = "access_token", length = 1000)
    private String accessToken; //Optional: store for API calls

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
