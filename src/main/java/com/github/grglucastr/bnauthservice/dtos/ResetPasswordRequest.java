package com.github.grglucastr.bnauthservice.dtos;

public record ResetPasswordRequest(String token, String newPassword) {
}
