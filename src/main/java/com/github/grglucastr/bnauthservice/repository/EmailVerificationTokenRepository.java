package com.github.grglucastr.bnauthservice.repository;

import com.github.grglucastr.bnauthservice.entity.EmailVerificationToken;
import com.github.grglucastr.bnauthservice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Long> {

    Optional<EmailVerificationToken> findByToken(String token);

    Optional<EmailVerificationToken> findByUser(User user);

    @Modifying(clearAutomatically = true)
    @Query("DELETE FROM EmailVerificationToken e WHERE e.user.id = :userId")
    void deleteByUserId(Long userId);

    void deleteByExpiresAtBefore(LocalDateTime now);

}