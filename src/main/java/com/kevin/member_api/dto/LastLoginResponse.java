package com.kevin.member_api.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.time.OffsetDateTime;

@Schema(description = "最後登入時間回應")
public class LastLoginResponse {

    @Schema(description = "最後登入時間 (RFC3339/UTC)", example = "2025-10-01T03:10:20Z")
    private OffsetDateTime lastLoginAt;

    @Schema(description = "最後登入的 IP 位址", example = "192.168.1.100")
    private String ipAddress;

    public LastLoginResponse() {}

    public LastLoginResponse(OffsetDateTime lastLoginAt) {
        this.lastLoginAt = lastLoginAt;
    }

    public LastLoginResponse(OffsetDateTime lastLoginAt, String ipAddress) {
        this.lastLoginAt = lastLoginAt;
        this.ipAddress = ipAddress;
    }

    public OffsetDateTime getLastLoginAt() {
        return lastLoginAt;
    }

    public void setLastLoginAt(OffsetDateTime lastLoginAt) {
        this.lastLoginAt = lastLoginAt;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }
}