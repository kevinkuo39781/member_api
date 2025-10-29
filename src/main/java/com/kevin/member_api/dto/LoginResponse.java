package com.kevin.member_api.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "登入回應")
public class LoginResponse {

    @Schema(description = "挑戰 ID", example = "challenge-123")
    private String challengeId;

    @Schema(description = "多因子認證方式", example = "email_otp")
    private String mfa;

    public LoginResponse() {}

    public LoginResponse(String challengeId, String mfa) {
        this.challengeId = challengeId;
        this.mfa = mfa;
    }

    public String getChallengeId() {
        return challengeId;
    }

    public void setChallengeId(String challengeId) {
        this.challengeId = challengeId;
    }

    public String getMfa() {
        return mfa;
    }

    public void setMfa(String mfa) {
        this.mfa = mfa;
    }
}