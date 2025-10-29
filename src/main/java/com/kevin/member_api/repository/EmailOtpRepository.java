package com.kevin.member_api.repository;

import com.kevin.member_api.entity.EmailOtp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

public interface EmailOtpRepository extends JpaRepository<EmailOtp, UUID> {

    Optional<EmailOtp> findTopByUserIdAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(UUID userId, String purpose);

    @Modifying
    @Query("UPDATE EmailOtp o SET o.consumedAt = :consumedAt WHERE o.user.id = :userId AND o.purpose = :purpose AND o.consumedAt IS NULL")
    void invalidateOldOtps(UUID userId, String purpose, OffsetDateTime consumedAt);

    @Modifying
    @Query("UPDATE EmailOtp o SET o.consumedAt = :consumedAt WHERE o.id = :otpId")
    void markAsConsumed(UUID otpId, OffsetDateTime consumedAt);
}