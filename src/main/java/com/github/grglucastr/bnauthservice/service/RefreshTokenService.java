package com.github.grglucastr.bnauthservice.service;

import com.github.grglucastr.bnauthservice.entity.RefreshToken;
import com.github.grglucastr.bnauthservice.entity.User;
import com.github.grglucastr.bnauthservice.repository.RefreshTokenRepository;
import com.github.grglucastr.bnauthservice.repository.UserRepository;
import com.github.grglucastr.bnauthservice.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    @Value("${jwt.refresh-token-expiration}")
    private Long refreshTokenExpiration;

    public RefreshToken createRefreshToken(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        refreshTokenRepository.deleteByUser(user);

        UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                .username(username)
                .password(user.getPassword())
                .authorities("USER")
                .build();

        String tokenString = jwtUtil.generateRefreshToken(userDetails);

        RefreshToken refreshToken = RefreshToken.builder()
                .token(tokenString)
                .user(user)
                .expiresAt(LocalDateTime.now().plusSeconds(refreshTokenExpiration / 1000))
                .build();

        RefreshToken saved = refreshTokenRepository.save(refreshToken);
        log.info("Created refresh token for user: {}", username);
        return saved;
    }

    public RefreshToken verifyRefreshToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Refresh token not found"));

        if(refreshToken.getRevoked())
            throw new IllegalArgumentException("Refresh token is already revoked");

        if(refreshToken.isExpired()){
            refreshTokenRepository.delete(refreshToken);
            throw new IllegalArgumentException("Refresh token is expired");
        }

        return refreshToken;
    }

    @Transactional
    public void revokeRefreshToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Refresh token not found"));

        refreshToken.setRevoked(true);
        refreshTokenRepository.save(refreshToken);
        log.info("Revoked refresh token for user: {}", refreshToken.getUser().getUsername());
    }

}
