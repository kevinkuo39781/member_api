package com.kevin.member_api.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "僅包含 Access Token 的回應")
public class AccessTokenResponse {

    @Schema(description = "新的存取令牌", example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")
    private String accessToken;

    @Schema(description = "令牌類型", example = "Bearer")
    private String tokenType = "Bearer";

    public AccessTokenResponse(String accessToken) {
        this.accessToken = accessToken;
    }

    // Getters and Setters
    public String getAccessToken() { return accessToken; }
    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
    public String getTokenType() { return tokenType; }
    public void setTokenType(String tokenType) { this.tokenType = tokenType; }
}
