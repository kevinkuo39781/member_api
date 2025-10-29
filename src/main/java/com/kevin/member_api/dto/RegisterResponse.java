package com.kevin.member_api.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.UUID;

@Schema(description = "註冊回應")
public class RegisterResponse {

    @Schema(description = "用戶 ID", example = "550e8400-e29b-41d4-a716-446655440000")
    private UUID userId;

    @Schema(description = "帳號狀態", example = "pending_activation")
    private String status;

    public RegisterResponse() {}

    public RegisterResponse(UUID userId, String status) {
        this.userId = userId;
        this.status = status;
    }

    public UUID getUserId() {
        return userId;
    }

    public void setUserId(UUID userId) {
        this.userId = userId;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}