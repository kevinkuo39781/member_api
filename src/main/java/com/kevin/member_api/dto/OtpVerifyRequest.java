package com.kevin.member_api.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

@Schema(description = "OTP 驗證請求")
public class OtpVerifyRequest {

    @Schema(description = "挑戰 ID", example = "challenge-123")
    @NotBlank(message = "Challenge ID 不能為空")
    private String challengeId;

    @Schema(description = "6 位數 OTP 驗證碼", example = "123456")
    @NotBlank(message = "OTP 不能為空")
    @Pattern(regexp = "^\\d{6}$", message = "OTP 必須是 6 位數字")
    private String otp;

    public OtpVerifyRequest() {}

    public OtpVerifyRequest(String challengeId, String otp) {
        this.challengeId = challengeId;
        this.otp = otp;
    }

    public String getChallengeId() {
        return challengeId;
    }

    public void setChallengeId(String challengeId) {
        this.challengeId = challengeId;
    }

    public String getOtp() {
        return otp;
    }

    public void setOtp(String otp) {
        this.otp = otp;
    }
}