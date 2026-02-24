package com.github.grglucastr.bnauthservice.dtos;

public record TwoFactorVerifyRequest(String username, String otpCode) {
}
