package com.github.grglucastr.bnauthservice.controller;

import com.github.grglucastr.bnauthservice.dtos.ErrorResponse;
import com.github.grglucastr.bnauthservice.dtos.RegisterRequest;
import com.github.grglucastr.bnauthservice.dtos.RegisterResponse;
import com.github.grglucastr.bnauthservice.entity.EmailVerificationToken;
import com.github.grglucastr.bnauthservice.entity.User;
import com.github.grglucastr.bnauthservice.service.EmailService;
import com.github.grglucastr.bnauthservice.service.EmailVerificationService;
import com.github.grglucastr.bnauthservice.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/registrations")
@RequiredArgsConstructor
public class RegisterController {

    private final UserService userService;
    private final EmailVerificationService emailVerificationService;
    private final EmailService emailService;

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE,
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

}
