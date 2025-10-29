package com.kevin.member_api.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "重寄 OTP 請求")
public class ResendOtpRequest {

    @NotBlank(message = "Challenge ID cannot be blank")
    @Schema(description = "第一階段登入後取得的 Challenge ID", requiredMode = Schema.RequiredMode.REQUIRED)
    private String challengeId;

    public String getChallengeId() {
        return challengeId;
    }

    public void setChallengeId(String challengeId) {
        this.challengeId = challengeId;
    }
}
