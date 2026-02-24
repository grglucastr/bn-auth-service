package com.github.grglucastr.bnauthservice.service;

import com.github.grglucastr.bnauthservice.entity.TwoFactorAuth;
import com.github.grglucastr.bnauthservice.entity.User;
import com.github.grglucastr.bnauthservice.repository.TwoFactorAuthRepository;
import com.github.grglucastr.bnauthservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class TwoFactorAuthService {

    private final TwoFactorAuthRepository twoFactorRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;

    private static final int OTP_EXPIRATION_MINUTES = 5;
    private static final int OTP_LENGTH = 6;

    //Check if user has 2FA enabled
    public boolean is2FAEnabled(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return twoFactorRepository.findByUser(user)
                .map(TwoFactorAuth::getEnabled)
                .orElse(false);
    }

    //Generate and send OTP code
    @Transactional
    public void generateAndSendOTP(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Generate 6-digit OTP
        String otpCode = generateOTP();

        // Find or create 2FA record
        TwoFactorAuth twoFactorAuth = twoFactorRepository.findByUser(user)
                .orElse(TwoFactorAuth.builder()
                        .user(user)
                        .enabled(true)
                        .build());

        // Set OTP and expiration
        twoFactorAuth.setOtpCode(otpCode);
        twoFactorAuth.setOtpExpiresAt(LocalDateTime.now().plusMinutes(OTP_EXPIRATION_MINUTES));
        twoFactorAuth.setOtpVerified(false);

        twoFactorRepository.save(twoFactorAuth);

        // Send OTP via email
        // TODO: call email service here
        // emailService.send2FACode(user.getEmail(), otpCode);

        log.info("OTP generated and sent to user: {}", username);
    }

    // Verify OTP code
    @Transactional
    public boolean verifyOTP(String username, String otpCode) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        TwoFactorAuth twoFactorAuth = twoFactorRepository.findByUser(user)
                .orElseThrow(() -> new IllegalStateException("2FA not configured for user"));


        if (twoFactorAuth.isOtpValid(otpCode)) {
            // Mark OTP as verified
            twoFactorAuth.setOtpVerified(true);
            twoFactorRepository.save(twoFactorAuth);

            log.info("OTP verified successfully for user: {}", username);
            return true;
        }

        log.error("Invalid or expired OTP for user: {}", username);
        return false;
    }

    // Enable or disable 2FA for user
    @Transactional
    public void toggle2FA(String username, boolean enable) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        TwoFactorAuth twoFactorAuth = twoFactorRepository.findByUser(user)
                .orElse(TwoFactorAuth.builder()
                        .user(user)
                        .build());

        twoFactorAuth.setEnabled(enable);
        twoFactorRepository.save(twoFactorAuth);

        log.info("2FA {} for user: {}", enable ? "enabled" : "disabled", username);
    }

    // Generate random 6-digit OTP
    private String generateOTP() {
        SecureRandom random = new SecureRandom();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }
}
