package com.github.grglucastr.bnauthservice.repository;

import com.github.grglucastr.bnauthservice.entity.TwoFactorAuth;
import com.github.grglucastr.bnauthservice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TwoFactorAuthRepository extends JpaRepository<TwoFactorAuth, Long> {

    Optional<TwoFactorAuth> findByUser(User user);

    boolean existsByUser(User user);

}
