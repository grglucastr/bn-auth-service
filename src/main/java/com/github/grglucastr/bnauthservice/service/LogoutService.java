package com.github.grglucastr.bnauthservice.service;

import com.github.grglucastr.bnauthservice.entity.User;
import com.github.grglucastr.bnauthservice.repository.RefreshTokenRepository;
import com.github.grglucastr.bnauthservice.repository.UserRepository;
import com.github.grglucastr.bnauthservice.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class LogoutService {

    private final TokenBlackListService tokenBlackListService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    @Transactional
    public void logout(String token){
        String username = jwtUtil.extractUsername(token);

        tokenBlackListService.blacklistToken(token);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Username not found"));

        refreshTokenRepository.deleteByUser(user);

        log.info("User {} logged out successfully", username);
    }

    public void logoutFromAllDevices(String token){
        String username = jwtUtil.extractUsername(token);

        tokenBlackListService.blacklistToken(token);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Username not found"));

        refreshTokenRepository.deleteByUser(user);

        log.info("User {} logged out from all successfully", username);
    }
}
