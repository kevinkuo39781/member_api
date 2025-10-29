package com.kevin.member_api.controller;

import com.kevin.member_api.dto.*;
import com.kevin.member_api.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication API", description = "認證相關 API")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/register")
    @Operation(summary = "用戶註冊", description = "使用 Email 和密碼註冊新用戶")
    @ApiResponses({
        @ApiResponse(responseCode = "201", description = "註冊成功"),
        @ApiResponse(responseCode = "400", description = "請求參數錯誤"),
        @ApiResponse(responseCode = "409", description = "Email 已被註冊")
    })
    public ResponseEntity<RegisterResponse> register(
            @Valid @RequestBody AuthRequest request,
            HttpServletRequest httpRequest) {
        String ipAddr = getClientIpAddress(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        RegisterResponse response = authService.register(request, ipAddr, userAgent);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/activate")
    @Operation(summary = "啟用帳號", description = "使用啟用 token 啟用用戶帳號")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "啟用成功",
            content = @Content(mediaType = "application/json",
                schema = @Schema(implementation = ActivationResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid token"),
        @ApiResponse(responseCode = "410", description = "Token 已過期")
    })
    public ResponseEntity<ActivationResponse> activate(@RequestParam String token) {
        authService.activate(token);
        return ResponseEntity.ok(new ActivationResponse("activated"));
    }

    @PostMapping("/login")
    @Operation(summary = "第一階段登入", description = "使用 Email 和密碼進行第一階段認證")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "第一階段認證成功，已發送 OTP"),
        @ApiResponse(responseCode = "401", description = "認證失敗"),
        @ApiResponse(responseCode = "423", description = "帳號被鎖定或未啟用")
    })
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody AuthRequest request,
            HttpServletRequest httpRequest) {
        String ipAddr = getClientIpAddress(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        LoginResponse response = authService.login(request, ipAddr, userAgent);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login/verify")
    @Operation(summary = "第二階段登入", description = "驗證 OTP 並完成登入流程")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "登入成功"),
        @ApiResponse(responseCode = "401", description = "OTP 驗證失敗"),
        @ApiResponse(responseCode = "410", description = "Challenge 已過期")
    })
    public ResponseEntity<TokenResponse> verifyLogin(
            @Valid @RequestBody OtpVerifyRequest request,
            HttpServletRequest httpRequest) {
        String ipAddr = getClientIpAddress(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        TokenResponse response = authService.verifyOtp(request, ipAddr, userAgent);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-activation")
    @Operation(summary = "重寄啟用信", description = "重新發送帳號啟用信件。為防止用戶枚舉，無論email是否存在或已啟用，此請求一律回傳成功。")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "請求已受理"),
        @ApiResponse(responseCode = "429", description = "請求過於頻繁，請稍後再試")
    })
    public ResponseEntity<Void> resendActivation(@Valid @RequestBody EmailRequest request) {
        authService.resendActivationEmail(request.getEmail());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/otp/resend")
    @Operation(summary = "重寄 OTP", description = "重新發送登入用的 OTP")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "請求已受理"),
        @ApiResponse(responseCode = "429", description = "請求過於頻繁，請稍後再試")
    })
    public ResponseEntity<Void> resendOtp(@Valid @RequestBody ResendOtpRequest request) {
        authService.resendLoginOtp(request.getChallengeId());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/logout")
    @Operation(summary = "用戶登出", description = "註銷一個 Refresh Token，使其失效。此操作需要有效的 Access Token 進行認證。")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "登出成功，Token 已註銷"),
        @ApiResponse(responseCode = "401", description = "認證失敗或Token不匹配")
    })
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody RefreshTokenRequest request) {
        authService.logout(jwt, request.getRefreshToken());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/token/refresh")
    @Operation(summary = "刷新 Access Token", description = "使用 Refresh Token 換取新的 Access Token")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "刷新成功",
            content = @Content(mediaType = "application/json",
                schema = @Schema(implementation = AccessTokenResponse.class))),
        @ApiResponse(responseCode = "401", description = "Refresh Token 無效或已過期")
    })
    public ResponseEntity<AccessTokenResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        AccessTokenResponse response = authService.refreshToken(request.getRefreshToken());
        return ResponseEntity.ok(response);
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }
}
