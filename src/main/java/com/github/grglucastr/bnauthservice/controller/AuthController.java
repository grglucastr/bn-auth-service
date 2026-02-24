package com.github.grglucastr.bnauthservice.controller;

import com.github.grglucastr.bnauthservice.dtos.ErrorResponse;
import com.github.grglucastr.bnauthservice.dtos.ForgotPasswordRequest;
import com.github.grglucastr.bnauthservice.dtos.LoginRequest;
import com.github.grglucastr.bnauthservice.dtos.LoginResponse;
import com.github.grglucastr.bnauthservice.dtos.MessageResponse;
import com.github.grglucastr.bnauthservice.dtos.RegisterRequest;
import com.github.grglucastr.bnauthservice.dtos.RegisterResponse;
import com.github.grglucastr.bnauthservice.dtos.ResetPasswordRequest;
import com.github.grglucastr.bnauthservice.dtos.TwoFactorResponse;
import com.github.grglucastr.bnauthservice.entity.EmailVerificationToken;
import com.github.grglucastr.bnauthservice.entity.PasswordResetToken;
import com.github.grglucastr.bnauthservice.entity.RefreshToken;
import com.github.grglucastr.bnauthservice.entity.User;
import com.github.grglucastr.bnauthservice.service.EmailService;
import com.github.grglucastr.bnauthservice.service.EmailVerificationService;
import com.github.grglucastr.bnauthservice.service.LogoutService;
import com.github.grglucastr.bnauthservice.service.PasswordResetService;
import com.github.grglucastr.bnauthservice.service.RefreshTokenService;
import com.github.grglucastr.bnauthservice.service.TwoFactorAuthService;
import com.github.grglucastr.bnauthservice.service.UserService;
import com.github.grglucastr.bnauthservice.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final UserService userService;
    private final RefreshTokenService refreshTokenService;
    private final PasswordResetService passwordResetService;
    private final EmailService emailService;
    private final EmailVerificationService emailVerificationService;
    private final LogoutService logoutService;
    private final TwoFactorAuthService twoFactorAuthService;

    @PostMapping(value = "/login",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> login(@RequestBody LoginRequest login) {

        try {
            authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(
                            login.username(), login.password()
                    ));

            // Check if user has 2FA enabled
            if (twoFactorAuthService.is2FAEnabled(login.username())) {
                // Generate and send OTP
                twoFactorAuthService.generateAndSendOTP(login.username());

                log.info("2FA required for user: {}", login.username());

                return ResponseEntity.ok(new TwoFactorResponse(
                        "2FA code sent to your email. Please verify to complete login.",
                        true,
                        login.username()
                ));
            }

            // No 2FA - proceed with normal login
            UserDetails userDetails = userDetailsService.loadUserByUsername(login.username());
            String token = jwtUtil.generateAccessToken(userDetails);
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getUsername());

            log.info("User {} logged in successfully", userDetails.getUsername());

            return ResponseEntity.ok(new LoginResponse(
                    "Login successful!",
                    login.username(),
                    token,
                    refreshToken.getToken()));

        } catch (AuthenticationException e) {
            log.error("Login failed for user: {}", login.username());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Invalid username or password"));
        } catch (Exception e) {
            log.error("Login failed for user {}: {}", login.username(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Account not verified. Please check your email."));
        }
    }

    @PostMapping(value = "/refresh",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
        try {
            String refreshToken = request.get("refreshToken");

            if (refreshToken == null || refreshToken.isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(new ErrorResponse("Refresh token is required"));
            }

            RefreshToken validRefreshToken = refreshTokenService.verifyRefreshToken(refreshToken);

            UserDetails userDetails = userDetailsService.loadUserByUsername(
                    validRefreshToken.getUser().getUsername());

            String newAccessToken = jwtUtil.generateAccessToken(userDetails);

            log.info("Access token refreshed for user: {}", userDetails.getUsername());

            return ResponseEntity.ok(Map.of(
                    "accessToken", newAccessToken,
                    "message", "Token refreshed successfully"));

        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse(e.getMessage()));
        }
    }

    @PostMapping(value = "/register",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        try {
            User user = userService.registerUser(
                    request.username(),
                    request.email(),
                    request.password()
            );

            // Create verification token
            EmailVerificationToken verificationToken = emailVerificationService.createVerificationToken(user);

            // Send verification email
            emailService.sendVerificationEmail(user.getEmail(), verificationToken.getToken());

            log.info("User {} registered successfully", user.getUsername());

            return ResponseEntity.ok(new RegisterResponse("User registered successfully!",
                    user.getUsername(),
                    user.getEmail()));

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse(e.getMessage()));
        }
    }

    @PostMapping(value = "/forgot-password",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        try {

            PasswordResetToken resetToken = passwordResetService
                    .createPasswordResetToken(request.email());

            emailService.sendPasswordResetEmail(request.email(), resetToken.getToken());

            log.info("Password reset requested for email: {}", request.email());

            return ResponseEntity.ok(new MessageResponse(
                    "If your email exists in our system, you will receive a password password reset link"
            ));

        } catch (UsernameNotFoundException e) {
            log.error("Password reset requested for non-existent email: {}", request.email());
            return ResponseEntity.ok(new MessageResponse(
                    "If your email exists in our system, you will receive a password reset link"
            ));
        }
    }

    @PostMapping(value = "/reset-password",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest request) {
        try {

            passwordResetService.resetPassword(request.token(), request.newPassword());

            return ResponseEntity.ok(new MessageResponse(
                    "Password has been reset successfully. You can login now with your new password."));

        } catch (IllegalArgumentException e) {
            log.error("Password reset failed: {}", e.getMessage());
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse(e.getMessage()));

        }
    }

    @GetMapping(value = "/verify-reset-token",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> verifyResetToken(@RequestParam String token) {
        try {
            PasswordResetToken resetToken = passwordResetService.verifyToken(token);

            return ResponseEntity.ok(Map.of(
                    "valild", true,
                    "email", resetToken.getUser().getEmail(),
                    "expiresAt", resetToken.getExpiresAt()
            ));

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "valid", false,
                            "error", e.getMessage()
                    ));
        }
    }

    @GetMapping(value = "/verify-email",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> verifyEmail(@RequestParam String token) {
        try {
            emailVerificationService.verifyEmail(token);

            return ResponseEntity.ok(new MessageResponse(
                    "Email verified successfully! You can now login."));

        } catch (IllegalArgumentException e) {
            log.error("Email verification failed: {}", e.getMessage());
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse(e.getMessage()));
        }
    }

    @PostMapping(value = "/resend-verification",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> resendVerification(@RequestBody Map<String, String> request) {
        try {
            String email = request.get("email");

            if (email == null || email.isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(new ErrorResponse("Email is required."));
            }

            EmailVerificationToken verificationToken = emailVerificationService.resendVerificationEmail(email);
            emailService.sendVerificationEmail(email, verificationToken.getToken());

            return ResponseEntity.ok(new MessageResponse(
                    "Verification email has been resent. Please check your inbox."
            ));

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse(e.getMessage()));
        }
    }

    @PostMapping(value = "/logout",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> logout(HttpServletRequest request) {
        try {
            String authHeader = request.getHeader("Authorization");

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.badRequest()
                        .body(new ErrorResponse("No token provided"));
            }

            String token = authHeader.substring(7);
            logoutService.logout(token);

            return ResponseEntity.ok(new MessageResponse("Logged out successfully"));
        } catch (Exception e) {
            log.error("Logout failed: {}", e.getMessage());
            return ResponseEntity.internalServerError()
                    .body(new ErrorResponse("Logout failed"));
        }
    }

    @PostMapping(value = "/logout-all",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> logoutFromAllDevices(HttpServletRequest request) {
        try {
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.badRequest()
                        .body(new ErrorResponse("No token provided"));
            }

            String token = authHeader.substring(7);
            logoutService.logoutFromAllDevices(token);

            // TODO: In a full implementation, you'd also need to track and blacklist
            // all active access tokens for this user

            return ResponseEntity.ok(new MessageResponse(
                    "Logged out from all devices successfully"));
        } catch (Exception e) {
            log.error("Logout from all devices failed: {}", e.getMessage());
            return ResponseEntity.internalServerError()
                    .body(new ErrorResponse("Logout failed"));
        }
    }


    @GetMapping(value = "/me", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getCurrentUser() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        return ResponseEntity.ok(Map.of(
                "username", authentication.getName(),
                "authorities", authentication.getAuthorities()));
    }

}
