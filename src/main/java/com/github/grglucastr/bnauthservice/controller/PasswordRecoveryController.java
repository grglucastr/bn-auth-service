package com.github.grglucastr.bnauthservice.controller;

import com.github.grglucastr.bnauthservice.dtos.ErrorResponse;
import com.github.grglucastr.bnauthservice.dtos.ForgotPasswordRequest;
import com.github.grglucastr.bnauthservice.dtos.MessageResponse;
import com.github.grglucastr.bnauthservice.dtos.ResetPasswordRequest;
import com.github.grglucastr.bnauthservice.entity.PasswordResetToken;
import com.github.grglucastr.bnauthservice.service.EmailService;
import com.github.grglucastr.bnauthservice.service.PasswordResetService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/passwords")
@RequiredArgsConstructor
public class PasswordRecoveryController {

    private final PasswordResetService passwordResetService;
    private final EmailService emailService;

    @PutMapping(value = "/reset-requests",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> updatePassword(@RequestBody ResetPasswordRequest request) {
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

    @RequestMapping(value = "/reset-requests",
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
}
