package io.assignment.auth.repository;

import io.assignment.auth.domain.Role;
import io.assignment.auth.domain.UserRole;
import io.assignment.auth.domain.UserRoleId; // Added this import
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface UserRoleRepository extends JpaRepository<UserRole, UserRoleId> { // Changed Long to UserRoleId
    @Query("select ur.id.role from UserRole ur where ur.id.userId = :userId") // Modified query
    List<Role> findRolesByUserId(Long userId);

    default List<String> findRoleNamesByUserId(Long userId) {
        return findRolesByUserId(userId).stream().map(Enum::name).toList();
    }
}
