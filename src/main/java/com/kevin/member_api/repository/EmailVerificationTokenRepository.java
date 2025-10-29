package com.kevin.member_api.repository;

import com.kevin.member_api.entity.EmailVerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, UUID> {

    Optional<EmailVerificationToken> findByTokenHashAndConsumedAtIsNull(String tokenHash);

    @Modifying
    @Query("UPDATE EmailVerificationToken t SET t.consumedAt = :consumedAt WHERE t.id = :tokenId")
    void markAsConsumed(@Param("tokenId") UUID tokenId, @Param("consumedAt") OffsetDateTime consumedAt);

    @Modifying
    @Query("DELETE FROM EmailVerificationToken t WHERE t.expiresAt < :now")
    void deleteExpiredTokens(@Param("now") OffsetDateTime now);

    @Query("SELECT COUNT(t) FROM EmailVerificationToken t WHERE t.user.id = :userId AND t.createdAt > :since")
    long countByUserIdAndCreatedAtAfter(@Param("userId") UUID userId, @Param("since") OffsetDateTime since);
}