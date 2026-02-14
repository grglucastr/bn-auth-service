package com.github.grglucastr.bnauthservice.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class EmailService {

    public void sendPasswordResetEmail(String email, String resetToken) {

        String resetLink = "http://localhost:8080/reset-password?token=" + resetToken;

        log.info("=".repeat(80));
        log.info("📧 PASSWORD RESET MAIL (Simulated)");
        log.info("To: {}", email);

        log.info("Subject: Reset Your Password");
        log.info("");
        log.info("Click the link below to reset your password: ");
        log.info("{}", resetLink);
        log.info("");
        log.info("This link will expire in 1 hour.");
        log.info("If you didn't request this, please ignore this email.");

        log.info("=".repeat(80));
    }
}
