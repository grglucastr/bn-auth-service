package com.github.grglucastr.bnauthservice.config;

import com.github.grglucastr.bnauthservice.entity.User;
import com.github.grglucastr.bnauthservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class DataInitializer {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Bean
    public CommandLineRunner initDatabase() throws Exception {
        return args -> {
            if (userRepository.count() == 0) {
                log.info("Initializing database with test users...");

                User john = User.builder()
                        .username("john")
                        .email("john@example.com")
                        .password(passwordEncoder.encode("pass123"))
                        .roles(Set.of("USER"))
                        .enabled(true)
                        .build();

                User admin = User.builder()
                        .username("admin")
                        .email("admin@example.com")
                        .password(passwordEncoder.encode("pass123"))
                        .roles(Set.of("USER", "ADMIN"))
                        .enabled(true)
                        .build();

                userRepository.save(john);
                userRepository.save(admin);

                log.info("Test users created successfully!");
            }
        };
    }
}
