package com.github.grglucastr.bnauthservice.service;

import com.github.grglucastr.bnauthservice.entity.PasswordResetToken;
import com.github.grglucastr.bnauthservice.entity.User;
import com.github.grglucastr.bnauthservice.repository.PasswordResetTokenRepository;
import com.github.grglucastr.bnauthservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final PasswordResetTokenRepository resetTokenRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private static final int EXPIRATION_HOURS = 1;

    @Transactional
    public PasswordResetToken createPasswordResetToken(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

        // Delete any existing reset tokens for this user
        resetTokenRepository.deleteByUser(user);

        String token = UUID.randomUUID().toString();

        PasswordResetToken resetToken = PasswordResetToken.builder()
                .token(token)
                .user(user)
                .used(false)
                .expiresAt(LocalDateTime.now().plusHours(EXPIRATION_HOURS))
                .build();

        PasswordResetToken saved = resetTokenRepository.save(resetToken);
        log.info("Password reset token created for user: {}", email);
        return saved;
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {
        PasswordResetToken resetToken = resetTokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid reset token"));

        if (resetToken.isInvalid()) {
            log.error("Token is used or expired.");
            throw new IllegalArgumentException("Password reset token is expired or already used");
        }

        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        resetToken.setUsed(true);
        resetTokenRepository.save(resetToken);

        log.info("Password reset successfully for user: {}", user.getUsername());
    }

    public PasswordResetToken verifyToken(String token) {
        PasswordResetToken resetToken = resetTokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid password reset token"));

        if (resetToken.isInvalid()) {
            log.error("Token is used or expired.");
            throw new IllegalStateException("Password reset token is expired or already used");
        }

        return resetToken;
    }

    // Cleanup expired tokens (can be scheduled)
    @Transactional
    public void cleanUpExpiredTokens() {
        resetTokenRepository.deleteByExpiresAtBefore(LocalDateTime.now());
    }
}
