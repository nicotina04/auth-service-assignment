package io.assignment.auth.domain;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.util.Base64;

@Entity
@Table(
        name = "refresh_tokens",
        indexes = {
                @Index(name = "idx_refresh_tokens_user_id", columnList = "user_id"),
                @Index(name = "idx_refresh_tokens_expires_at", columnList = "expires_at")
        },
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_refresh_tokens_token_hash", columnNames = {"token_hash"})
        }
)
@Getter @Setter
@NoArgsConstructor
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;

    @NotNull
    @Column(name = "user_id", nullable = false)
    private Long userId;

    @NotNull
    @Column(name = "token_hash", nullable = false, length = 512, unique = true)
    private String tokenHash;

    @NotNull
    @Column(name = "issued_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime issuedAt;

    @NotNull
    @Column(name = "expires_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime expiresAt;

    @Column(name = "rotated_from")
    private Long rotatedFrom;

    @Column(name = "revoked_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime revokedAt;

    @Column(name = "user_agent", columnDefinition = "TEXT")
    private String userAgent;

    @Column(name = "ip_address", length = 45)
    private String ip;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;

    public static String hashToken(String plainToken) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(plainToken.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to hash refresh token", e);
        }
    }

    public void applyNewToken(String plainToken, OffsetDateTime now, OffsetDateTime exp) {
        this.tokenHash = hashToken(plainToken);
        this.issuedAt = now;
        this.expiresAt = exp;
        this.revokedAt = null;
    }

    public boolean isActive(OffsetDateTime now) {
        return revokedAt == null && (expiresAt == null || now.isBefore(expiresAt));
    }

    public static String randomToken() { byte[] buf = new byte[32]; new SecureRandom().nextBytes(buf); return Base64.getUrlEncoder().withoutPadding().encodeToString(buf); }
}
