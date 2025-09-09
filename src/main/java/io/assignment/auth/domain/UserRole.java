package io.assignment.auth.domain;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "user_roles")
@Data
@NoArgsConstructor
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class UserRole {
    @EmbeddedId
    @EqualsAndHashCode.Include
    private UserRoleId id;

    public UserRole(Long userId, Role role) {
        this.id = new UserRoleId(userId, role.name());
    }
}
