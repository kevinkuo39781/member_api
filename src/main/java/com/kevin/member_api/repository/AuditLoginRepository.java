package com.kevin.member_api.repository;

import com.kevin.member_api.entity.AuditLogin;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import org.springframework.data.jpa.repository.Query;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuditLoginRepository extends JpaRepository<AuditLogin, UUID> {

    @Query("SELECT a FROM AuditLogin a WHERE a.user.id = :userId AND a.stage = 'login_success' AND a.success = true ORDER BY a.createdAt DESC LIMIT 1")
    Optional<AuditLogin> findLastLoginByUserId(UUID userId);
}