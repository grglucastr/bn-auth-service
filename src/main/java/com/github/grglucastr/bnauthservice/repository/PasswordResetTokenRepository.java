package com.github.grglucastr.bnauthservice.repository;

import com.github.grglucastr.bnauthservice.entity.PasswordResetToken;
import com.github.grglucastr.bnauthservice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.Optional;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    Optional<PasswordResetToken> findByToken(String token);

    void deleteByUser(User user);

    void deleteByExpiresAtBefore(LocalDateTime now);
}
