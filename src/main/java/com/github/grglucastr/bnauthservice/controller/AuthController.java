package com.github.grglucastr.bnauthservice.controller;

import com.github.grglucastr.bnauthservice.dtos.*;
import com.github.grglucastr.bnauthservice.entity.RefreshToken;
import com.github.grglucastr.bnauthservice.entity.User;
import com.github.grglucastr.bnauthservice.service.RefreshTokenService;
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
import org.springframework.web.bind.annotation.*;

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

    @PostMapping(value = "/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> login(@RequestBody LoginRequest login, HttpServletRequest request) {

        try {
            authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(
                            login.username(), login.password()
                    ));

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
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Invalid username or password"));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
        try{
            String refreshToken = request.get("refreshToken");

            if(refreshToken == null || refreshToken.isEmpty()){
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

        }catch (IllegalArgumentException e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse(e.getMessage()));
        }
    }

    @PostMapping(value = "/register", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        try {

            User user = userService.registerUser(
                    request.username(),
                    request.email(),
                    request.password()
            );

            log.info("User {} registered successfully", user.getUsername());

            return ResponseEntity.ok(new RegisterResponse("User registered successfully!",
                    user.getUsername(),
                    user.getEmail()));

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
        }
    }

    @GetMapping("/me")
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
