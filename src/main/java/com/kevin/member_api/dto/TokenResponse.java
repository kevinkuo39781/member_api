package com.kevin.member_api.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Token 回應")
public class TokenResponse {

    @Schema(description = "存取令牌", example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")
    private String accessToken;

    @Schema(description = "令牌有效期（秒）", example = "900")
    private Integer expiresIn;

    @Schema(description = "刷新令牌", example = "refresh-token-123")
    private String refreshToken;

    @Schema(description = "令牌類型", example = "Bearer")
    private String tokenType = "Bearer";

    public TokenResponse() {}

    public TokenResponse(String accessToken, Integer expiresIn, String refreshToken) {
        this.accessToken = accessToken;
        this.expiresIn = expiresIn;
        this.refreshToken = refreshToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public Integer getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(Integer expiresIn) {
        this.expiresIn = expiresIn;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }
}