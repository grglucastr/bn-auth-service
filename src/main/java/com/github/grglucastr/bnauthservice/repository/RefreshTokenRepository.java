package com.github.grglucastr.bnauthservice.repository;

import com.github.grglucastr.bnauthservice.entity.RefreshToken;
import com.github.grglucastr.bnauthservice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {

    Optional<RefreshToken> findByToken(String token);

    void deleteByToken(String token);

    void deleteByUser(User user);
}
