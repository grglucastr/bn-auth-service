package com.github.grglucastr.bnauthservice.service;

import com.github.grglucastr.bnauthservice.entity.EmailVerificationToken;
import com.github.grglucastr.bnauthservice.entity.User;
import com.github.grglucastr.bnauthservice.repository.EmailVerificationTokenRepository;
import com.github.grglucastr.bnauthservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final EmailVerificationTokenRepository verificationTokenRepository;
    private final UserRepository userRepository;

    private static final int EXPIRATION_HOURS = 24;

    @Transactional
    public EmailVerificationToken createVerificationToken(User user) {
        // Delete any existing verification tokens for this user
        verificationTokenRepository.deleteByUserId(user.getId());

        String token = UUID.randomUUID().toString();

        EmailVerificationToken verificationToken = EmailVerificationToken.builder()
                .token(token)
                .user(user)
                .expiresAt(LocalDateTime.now().plusHours(EXPIRATION_HOURS))
                .build();

        EmailVerificationToken saved = verificationTokenRepository.save(verificationToken);
        log.info("Email verification token created for user: {}", user.getEmail());
        return saved;
    }

    @Transactional
    public void verifyEmail(String token) {
        EmailVerificationToken verificationToken = verificationTokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid verification token"));

        if (verificationToken.isVerified()) {
            log.error("Email verification token is already verified");
            throw new IllegalArgumentException("Email already verified");
        }

        if (verificationToken.isExpired()) {
            log.error("Email verification token is expired");
            throw new IllegalArgumentException("Verification token has expired");
        }

        verificationToken.setVerifiedAt(LocalDateTime.now());
        verificationTokenRepository.save(verificationToken);

        // Enable user account
        User user = verificationToken.getUser();
        user.setEnabled(true);
        userRepository.save(user);
        log.info("Email verified successfully for user: {}", user.getEmail());
    }

    @Transactional
    public EmailVerificationToken resendVerificationEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found with email: " + email));

        // Check if already verified
        if (user.getEnabled()) {
            log.error("Email already verified");
            throw new IllegalArgumentException("Email already verified");
        }

        return createVerificationToken(user);
    }

    @Transactional
    public void cleanupExpiredTokens() {
        verificationTokenRepository.deleteByExpiresAtBefore(LocalDateTime.now());
        log.info("Expired email verification tokens cleaned up");
    }


}
