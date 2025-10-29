package com.kevin.member_api.controller;

import com.kevin.member_api.dto.LastLoginResponse;
import com.kevin.member_api.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
@Tag(name = "User API", description = "用戶相關 API")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping("/me/last-login")
    @Operation(summary = "查詢最後登入時間", description = "查詢當前用戶的最後登入時間")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "查詢成功"),
        @ApiResponse(responseCode = "401", description = "未授權訪問"),
        @ApiResponse(responseCode = "404", description = "用戶不存在")
    })
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<LastLoginResponse> getLastLogin(@AuthenticationPrincipal Jwt jwt) {
        LastLoginResponse response = userService.getLastLogin(jwt);
        return ResponseEntity.ok(response);
    }
}