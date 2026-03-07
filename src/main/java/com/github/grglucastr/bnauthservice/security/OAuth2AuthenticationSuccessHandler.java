package com.github.grglucastr.bnauthservice.security;

import com.github.grglucastr.bnauthservice.entity.OAuth2Provider;
import com.github.grglucastr.bnauthservice.entity.RefreshToken;
import com.github.grglucastr.bnauthservice.entity.User;
import com.github.grglucastr.bnauthservice.repository.OAuth2ProviderRepository;
import com.github.grglucastr.bnauthservice.service.RefreshTokenService;
import com.github.grglucastr.bnauthservice.util.JwtUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final RefreshTokenService refreshTokenService;
    private final OAuth2ProviderRepository oAuth2ProviderRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();

        // Get provider from request
        String provider = extractProvider(request);

        // Get provider user ID
        String providerUserId = extractProviderUserId(oauth2User, provider);

        // Find OAuth2Provider Link
        OAuth2Provider oauth2Provider = oAuth2ProviderRepository
                .findByProviderAndProviderUserId(provider, providerUserId)
                .orElseThrow(() -> new RuntimeException("OAuth2 provider not found"));

        User user = oauth2Provider.getUser();

        // Generate JWT tokens
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        String accessToken = jwtUtil.generateAccessToken(userDetails);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getUsername());

        log.info("OAuth2 login successful for user: {}", user.getUsername());

        // Redirect to frontend with tokens (in production, use proper redirect)
        String redirectUrl = String.format(
                "http://localhost:8080/oauth2/success?accessToken=%s&refreshToken=%s",
                accessToken,
                refreshToken.getToken());

        getRedirectStrategy().sendRedirect(request, response, redirectUrl);

    }

    private String extractProvider(HttpServletRequest request) {
        String requestUri = request.getRequestURI();

        if (requestUri.contains("/google")) {
            return "google";
        }

        if (requestUri.contains("/github")) {
            return "github";
        }

        throw new RuntimeException("Unknown OAuth2 provider");
    }

    private String extractProviderUserId(OAuth2User oauth2User, String provider) {
        Map<String, Object> attributes = oauth2User.getAttributes();

        if (provider.equals("google")) {
            return (String) attributes.get("sub");

        } else if (provider.equals("github")) {
            return String.valueOf(attributes.get("id"));
        }

        throw new RuntimeException("Unknown provider");
    }
}
