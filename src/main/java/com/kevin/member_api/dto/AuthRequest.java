package com.kevin.member_api.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(description = "認證請求")
public class AuthRequest {

    @Schema(description = "電子郵件地址", example = "user@example.com")
    @NotBlank(message = "Email 不能為空")
    @Email(message = "Email 格式不正確")
    private String email;

    @Schema(description = "密碼", example = "abcdefghijkl")
    @NotBlank(message = "密碼不能為空")
    @Size(min = 12, max = 128, message = "密碼長度必須在 12-128 字元之間")
    private String password;

    public AuthRequest() {}

    public AuthRequest(String email, String password) {
        this.email = email;
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
