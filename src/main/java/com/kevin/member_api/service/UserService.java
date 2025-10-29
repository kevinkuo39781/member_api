package com.kevin.member_api.service;

import com.kevin.member_api.dto.LastLoginResponse;
import com.kevin.member_api.repository.AuditLoginRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@Transactional
public class UserService {

    @Autowired
    private AuditLoginRepository auditLoginRepository;

    public LastLoginResponse getLastLogin(Jwt jwt) {
        String userIdStr = jwt.getClaimAsString("uid");
        if (userIdStr == null) {
            throw new RuntimeException("Invalid user ID in token");
        }
        UUID userId = UUID.fromString(userIdStr);

        return auditLoginRepository.findLastLoginByUserId(userId)
                .map(audit -> new LastLoginResponse(audit.getCreatedAt(), audit.getIpAddr()))
                .orElse(null);
    }
}