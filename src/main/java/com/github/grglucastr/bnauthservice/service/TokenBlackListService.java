package com.github.grglucastr.bnauthservice.service;

import com.github.grglucastr.bnauthservice.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenBlackListService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final JwtUtil jwtUtil;

    private static final String BLACKLIST_PREFIX = "blacklist:token:";

    /**
     * Add token to blacklist
     * TTL is set to token's remaining lifetime
     */
    public void blacklistToken(String token) {

        try {
            String key = BLACKLIST_PREFIX + token;

            // Calculate remaining time until token expires
            Date expiration = jwtUtil.extractExpiration(token);
            long ttl = expiration.getTime() - System.currentTimeMillis();

            if (ttl < 0) {
                log.error("Attempted to blacklist an already expired token.");
                return;
            }

            // Store in redis with TTL (Redis will auto-delete when expired)
            redisTemplate.opsForValue().set(key, "blacklisted", ttl, TimeUnit.MILLISECONDS);
            log.info("Token blacklisted with TTL: {} ms", ttl);
        } catch (Exception e) {
            log.error("Error blacklisting token: {}", e.getMessage());
            throw new RuntimeException("Failed to blacklist token: ", e);
        }
    }

    /**
     * Check if token is blacklisted
     */
    public boolean isTokenBlacklisted(String token) {
        try{
            String key = BLACKLIST_PREFIX + token;
            Boolean exists = redisTemplate.hasKey(key);
            return exists != null && exists;
        } catch(Exception e){
            log.error("Error checking token blacklisted: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Blacklist all tokens for a specific user
     * Used for "logout from all devices"
     */
    public void blacklistAllUserTokens(String username){
        String pattern = BLACKLIST_PREFIX + "user:" + username + ":*";
        log.info("Blacklisting all tokens for user {}", username);
        Set<String> keys = redisTemplate.keys(pattern);

    }

    public void removeFromBlacklist(String token){
        String key = BLACKLIST_PREFIX + token;
        redisTemplate.delete(key);
        log.info("Token removed from blacklist");
    }

}
