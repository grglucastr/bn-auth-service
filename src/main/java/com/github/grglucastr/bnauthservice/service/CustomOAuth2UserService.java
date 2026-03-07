package com.github.grglucastr.bnauthservice.service;

import com.github.grglucastr.bnauthservice.entity.OAuth2Provider;
import com.github.grglucastr.bnauthservice.entity.User;
import com.github.grglucastr.bnauthservice.repository.OAuth2ProviderRepository;
import com.github.grglucastr.bnauthservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final OAuth2ProviderRepository oAuth2ProviderRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);

        // Get provider name (google, github, etc)
        String provider = userRequest.getClientRegistration().getRegistrationId();

        // Extract user info from OAuth2User
        Map<String, Object> attributes = oAuth2User.getAttributes();

        // Process the OAuth2 user
        processOAuth2User(provider, attributes);

        return oAuth2User;
    }

    private void processOAuth2User(String provider, Map<String, Object> attributes) {
        String providerUserId;
        String email;
        String name;
        String picture;

        if (provider.equals("google")) {
            providerUserId = (String) attributes.get("sub");
            email = (String) attributes.get("email");
            name = (String) attributes.get("name");
            picture = (String) attributes.get("picture");
        } else if (provider.equals("github")) {
            providerUserId = String.valueOf(attributes.get("id"));
            email = (String) attributes.get("email");
            name = (String) attributes.get("name");
            picture = (String) attributes.get("avatar_url");
        } else {
            log.error("Unsupported OAuth2 provider {}", provider);
            throw new OAuth2AuthenticationException("Unsupported OAuth2 provider");
        }

        log.info("OAuth2 login attempt - Provider: {}, Email: {}", provider, email);

        OAuth2Provider oauth2Provider = oAuth2ProviderRepository
                .findByProviderAndProviderUserId(provider, providerUserId)
                .orElseGet(() -> createNewOAuth2User(provider, providerUserId, email, name, picture));

        log.info("OAuth2 user processed: {}", oauth2Provider.getUser().getUsername());
    }

    private OAuth2Provider createNewOAuth2User(String provider, String providerUserId,
                                               String email, String name, String picture) {

        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {

                    log.info("Creating new user for OAuth2: {}", email);
                    String username = generateUsername(email, name);

                    return userRepository.save(User.builder()
                            .username(username)
                            .email(email)
                            .password(passwordEncoder.encode(UUID.randomUUID().toString()))
                            .roles(Set.of("USER"))
                            .enabled(true)
                            .build());
                });

        OAuth2Provider oAuth2Provider = OAuth2Provider.builder()
                .user(user)
                .provider(provider)
                .providerUserId(providerUserId)
                .providerEmail(email)
                .providerName(name)
                .providerPicture(picture)
                .build();

        return oAuth2ProviderRepository.save(oAuth2Provider);

    }

    private String generateUsername(String email, String name) {
        String baseUsername = email.split("@")[0];

        if (!userRepository.existsByUsername(baseUsername)) {
            return baseUsername;
        }

        // Try name-based username
        if (name != null && !name.isEmpty()) {
            String nameUsername = name.toLowerCase().replaceAll("\\s+", "");
            if (!userRepository.existsByUsername(nameUsername)) {
                return nameUsername;
            }
        }

        // Generate random username
        String randomUsername;
        do {
            randomUsername = baseUsername + "_" + UUID.randomUUID().toString().substring(0, 8);
        } while (userRepository.existsByUsername(randomUsername));

        return randomUsername;
    }

}
