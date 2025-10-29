package com.kevin.member_api.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "啟用狀態回應")
public class ActivationResponse {

    @Schema(description = "處理狀態", example = "activated")
    private String status;

    public ActivationResponse(String status) {
        this.status = status;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
