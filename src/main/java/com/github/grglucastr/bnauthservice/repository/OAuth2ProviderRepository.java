package com.github.grglucastr.bnauthservice.repository;

import com.github.grglucastr.bnauthservice.entity.OAuth2Provider;
import com.github.grglucastr.bnauthservice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OAuth2ProviderRepository extends JpaRepository<OAuth2Provider, Long> {

    Optional<OAuth2Provider> findByProviderAndProviderUserId(String provider, String providerUserId);

    List<OAuth2Provider> findByUser(User user);

    boolean existsByUserAndProvider(User user, String provider);

    void deleteByUserAndProvider(User user, String provider);

}
