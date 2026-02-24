package com.github.grglucastr.bnauthservice.dtos;

public record TwoFactorResponse(String message, boolean requires2FA, String username) {
}
