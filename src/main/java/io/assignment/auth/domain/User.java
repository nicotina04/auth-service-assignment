package io.assignment.auth.domain;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.time.OffsetDateTime;

@Entity
@Table(name = "users")
@Data
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class User {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;

    private String email;
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    private UserStatus status = UserStatus.ACTIVE;

    private boolean mfaEnabled;
    private String mfaSecret;

    private OffsetDateTime createdAt;
    private OffsetDateTime updatedAt;

    @Version
    private Long version;

    @PrePersist
    protected void onCreate() {
        var now = OffsetDateTime.now();
        if (email != null) {
            email = email.trim().toLowerCase();
        }
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    protected void onUpdate() {
        if (email == null) {
            return;
        }
        var now = OffsetDateTime.now();
        email = email.trim().toLowerCase();
        updatedAt = now;
    }
}
