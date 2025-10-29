package com.kevin.member_api.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/members")
@Tag(name = "Member API", description = "會員管理相關 API")
public class MemberController {

    @GetMapping("/status")
    @Operation(summary = "取得 API 狀態", description = "返回 Member API 的基本狀態資訊")
    public ResponseEntity<Map<String, Object>> getApiStatus() {
        Map<String, Object> response = Map.of(
            "status", "active",
            "message", "Member API is running successfully",
            "version", "1.0.0",
            "timestamp", System.currentTimeMillis()
        );
        return ResponseEntity.ok(response);
    }

    @GetMapping("/hello")
    @Operation(summary = "Hello World", description = "簡單的 Hello World 端點")
    public ResponseEntity<Map<String, String>> hello() {
        Map<String, String> response = Map.of(
            "message", "Hello from Member API!",
            "description", "這是一個簡單的測試端點"
        );
        return ResponseEntity.ok(response);
    }
}