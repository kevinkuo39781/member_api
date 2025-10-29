package com.kevin.member_api.service;

import com.kevin.member_api.dto.*;
import com.kevin.member_api.entity.*;
import com.kevin.member_api.exception.EmailConflictException;
import com.kevin.member_api.exception.InvalidCredentialsException;
import com.kevin.member_api.exception.RateLimitException;
import com.kevin.member_api.repository.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Formatter;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@Transactional
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private EmailVerificationTokenRepository tokenRepository;
    @Autowired
    private EmailOtpRepository otpRepository;
    @Autowired
    private AuditLoginRepository auditRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private EmailService emailService;
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    @Autowired
    private JwtEncoder jwtEncoder;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Value("${email.service.enabled:true}")
    private boolean emailEnabled;
    @Value("${app.security.jwt.access-token.expiration:900}")
    private long accessTokenExpiration;
    @Value("${app.security.jwt.refresh-token.expiration:31536000}")
    private long refreshTokenExpiration;
    @Value("${spring.security.oauth2.authorizationserver.issuer}")
    private String jwtIssuer;
    @Value("${app.security.activation-token.expiration:86400}")
    private long activationTokenExpiration;
    @Value("${app.security.otp.expiration:600}")
    private long otpExpiration;

    private final SecureRandom secureRandom = new SecureRandom();

    public RegisterResponse register(AuthRequest request, String ipAddr, String userAgent) {
        String email = request.getEmail().toLowerCase().trim();
        if (userRepository.findByEmail(email).isPresent()) {
            throw new EmailConflictException("Email already exists: " + email);
        }
        User user = new User();
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        user.setStatus(User.STATUS_PENDING_ACTIVATION);
        user = userRepository.save(user);
        sendActivationEmail(user);
        return new RegisterResponse(user.getId(), "pending_activation");
    }

    public void activate(String token) {
        String tokenHash = hashToken(token);
        EmailVerificationToken verificationToken = tokenRepository
            .findByTokenHashAndConsumedAtIsNull(tokenHash)
            .orElseThrow(() -> new InvalidCredentialsException("Invalid or expired activation token"));
        if (verificationToken.isExpired()) {
            throw new InvalidCredentialsException("Activation token has expired");
        }
        userRepository.activateUser(verificationToken.getUser().getId(), User.STATUS_ACTIVE);
        tokenRepository.markAsConsumed(verificationToken.getId(), OffsetDateTime.now());
    }

    public LoginResponse login(AuthRequest request, String ipAddr, String userAgent) {
        String email = request.getEmail().toLowerCase().trim();
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new InvalidCredentialsException("Invalid credentials"));
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            auditLogin(user, AuditLogin.STAGE_PASSWORD_OK, false, ipAddr, userAgent);
            throw new InvalidCredentialsException("Invalid credentials");
        }
        if (!user.isActive()) {
            throw new InvalidCredentialsException("Account not activated or locked");
        }
        auditLogin(user, AuditLogin.STAGE_PASSWORD_OK, true, ipAddr, userAgent);
        String challengeId = generateChallengeId();
        storeLoginChallenge(challengeId, user.getId());
        sendLoginOtp(user);
        auditLogin(user, AuditLogin.STAGE_OTP_SENT, true, ipAddr, userAgent);
        return new LoginResponse(challengeId, user.getMfaMethod());
    }

    public TokenResponse verifyOtp(OtpVerifyRequest request, String ipAddr, String userAgent) {
        UUID userId = getLoginChallenge(request.getChallengeId());
        if (userId == null) {
            throw new InvalidCredentialsException("Invalid or expired challenge");
        }
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new InvalidCredentialsException("User not found"));
        EmailOtp emailOtp = otpRepository
            .findTopByUserIdAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(userId, EmailOtp.PURPOSE_LOGIN_2FA)
            .orElseThrow(() -> new InvalidCredentialsException("No valid OTP found"));
        if (!emailOtp.isValid()) {
            throw new InvalidCredentialsException("OTP invalid or expired");
        }
        if (!passwordEncoder.matches(request.getOtp(), emailOtp.getCodeHash())) {
            emailOtp.incrementRetryCount();
            otpRepository.save(emailOtp);
            auditLogin(user, AuditLogin.STAGE_OTP_VERIFIED, false, ipAddr, userAgent);
            throw new InvalidCredentialsException("Invalid OTP");
        }
        otpRepository.markAsConsumed(emailOtp.getId(), OffsetDateTime.now());
        clearLoginChallenge(request.getChallengeId());
        userRepository.updateLastLoginAt(userId, OffsetDateTime.now());
        auditLogin(user, AuditLogin.STAGE_OTP_VERIFIED, true, ipAddr, userAgent);
        auditLogin(user, AuditLogin.STAGE_LOGIN_SUCCESS, true, ipAddr, userAgent);
        String accessToken = generateAccessToken(user);
        String refreshToken = generateAndSaveRefreshToken(user);
        return new TokenResponse(accessToken, (int) accessTokenExpiration, refreshToken);
    }

    public void logout(Jwt jwt, String rawRefreshToken) {
        String tokenHash = hashToken(rawRefreshToken);
        String userIdFromJwt = jwt.getClaimAsString("uid");

        refreshTokenRepository.findByTokenHash(tokenHash).ifPresent(token -> {
            // Check ownership: Ensure the user from the access token matches the owner of the refresh token
            if (!token.getUser().getId().toString().equals(userIdFromJwt)) {
                throw new InvalidCredentialsException("Refresh token does not belong to the authenticated user.");
            }

            if (!token.isRevoked()) {
                token.setRevokedAt(OffsetDateTime.now());
                refreshTokenRepository.save(token);
                logger.info("User {} logged out, refresh token revoked.", userIdFromJwt);
            }
        });
    }

    public AccessTokenResponse refreshToken(String rawRefreshToken) {
        String tokenHash = hashToken(rawRefreshToken);
        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new InvalidCredentialsException("Invalid refresh token"));
        if (refreshToken.isRevoked() || refreshToken.isExpired()) {
            throw new InvalidCredentialsException("Refresh token is revoked or expired");
        }
        User user = refreshToken.getUser();
        String newAccessToken = generateAccessToken(user);
        return new AccessTokenResponse(newAccessToken);
    }

    public void resendLoginOtp(String challengeId) {
        String rateLimitKey = "rate-limit:resend-otp:" + challengeId;
        if (redisTemplate.hasKey(rateLimitKey)) {
            throw new RateLimitException("Too many requests to resend OTP. Please try again later.");
        }
        UUID userId = getLoginChallenge(challengeId);
        redisTemplate.opsForValue().set(rateLimitKey, "locked", 60, TimeUnit.SECONDS);
        if (userId == null) {
            return;
        }
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found for given challenge"));
        logger.info("Resending login OTP to user {}", user.getEmail());
        sendLoginOtp(user);
    }

    public void resendActivationEmail(String email) {
        String normalizedEmail = email.toLowerCase().trim();
        String rateLimitKey = "rate-limit:resend-activation:" + normalizedEmail;
        if (Boolean.TRUE.equals(redisTemplate.hasKey(rateLimitKey))) {
            throw new RateLimitException("Too many requests to resend activation email. Please try again later.");
        }
        redisTemplate.opsForValue().set(rateLimitKey, "locked", 60, TimeUnit.SECONDS);
        userRepository.findByEmail(normalizedEmail).ifPresent(user -> {
            if (user.getStatus() == User.STATUS_PENDING_ACTIVATION) {
                logger.info("Resending activation email to {}", normalizedEmail);
                sendActivationEmail(user);
            }
        });
    }

    private String generateAndSaveRefreshToken(User user) {
        String token = generateSecureToken();
        String tokenHash = hashToken(token);
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setTokenHash(tokenHash);
        refreshToken.setExpiresAt(OffsetDateTime.now().plusSeconds(refreshTokenExpiration));
        refreshTokenRepository.save(refreshToken);
        return token;
    }

    private String generateAccessToken(User user) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(jwtIssuer)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(accessTokenExpiration))
                .subject(user.getEmail())
                .claim("uid", user.getId().toString())
                .build();
        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    private void sendActivationEmail(User user) {
        String token = generateSecureToken();
        String tokenHash = hashToken(token);
        EmailVerificationToken verificationToken = new EmailVerificationToken();
        verificationToken.setUser(user);
        verificationToken.setTokenHash(tokenHash);
        verificationToken.setExpiresAt(OffsetDateTime.now().plusSeconds(activationTokenExpiration));
        tokenRepository.save(verificationToken);
        if (!emailEnabled) {
            logger.info("===== LOCAL DEV: Activation Token for {} is: {} =====", user.getEmail(), token);
        }
        emailService.sendActivationEmail(user.getEmail(), token);
    }

        private void sendLoginOtp(User user) {

            // Check if an active OTP already exists

            Optional<EmailOtp> existingOtpOpt = otpRepository.findTopByUserIdAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(user.getId(), EmailOtp.PURPOSE_LOGIN_2FA);

            if (existingOtpOpt.isPresent() && !existingOtpOpt.get().isExpired()) {

                throw new RateLimitException("An active OTP already exists. Please try again after it expires.");

            }


            // Invalidate all previous login OTPs for this user (as a safeguard)

            otpRepository.invalidateOldOtps(user.getId(), EmailOtp.PURPOSE_LOGIN_2FA, OffsetDateTime.now());


            // Generate and send new OTP

            String otp = generateOtp();

            String otpHash = passwordEncoder.encode(otp);

            EmailOtp emailOtp = new EmailOtp();

            emailOtp.setUser(user);

            emailOtp.setCodeHash(otpHash);

            emailOtp.setPurpose(EmailOtp.PURPOSE_LOGIN_2FA);

            emailOtp.setExpiresAt(OffsetDateTime.now().plusSeconds(otpExpiration));

            otpRepository.save(emailOtp);


            if (!emailEnabled) {

                logger.info("===== LOCAL DEV: Login OTP for {} is: {} =====", user.getEmail(), otp);

            }

            emailService.sendOtpEmail(user.getEmail(), otp);
        }

    private String generateSecureToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String generateOtp() {
        return String.format("%06d", secureRandom.nextInt(1000000));
    }

    private String generateChallengeId() {
        return "challenge-" + UUID.randomUUID().toString();
    }

    private String hashToken(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(token.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            Formatter formatter = new Formatter();
            for (byte b : hashBytes) {
                formatter.format("%02x", b);
            }
            return formatter.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    private void storeLoginChallenge(String challengeId, UUID userId) {
        redisTemplate.opsForValue().set(
            "login:challenge:" + challengeId, 
            userId.toString(), 
            10, 
            TimeUnit.MINUTES
        );
    }

    private UUID getLoginChallenge(String challengeId) {
        String userIdStr = (String) redisTemplate.opsForValue().get("login:challenge:" + challengeId);
        return userIdStr != null ? UUID.fromString(userIdStr) : null;
    }

    private void clearLoginChallenge(String challengeId) {
        redisTemplate.delete("login:challenge:" + challengeId);
    }

    private void auditLogin(User user, String stage, boolean success, String ipAddr, String userAgent) {
        AuditLogin audit = new AuditLogin();
        audit.setUser(user);
        audit.setStage(stage);
        audit.setSuccess(success);
        audit.setIpAddr(ipAddr);
        audit.setUserAgent(userAgent);
        auditRepository.save(audit);
    }
}
