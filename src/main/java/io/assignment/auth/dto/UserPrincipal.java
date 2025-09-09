package io.assignment.auth.dto;

import io.assignment.auth.domain.UserStatus;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

@Getter
public class UserPrincipal implements OAuth2User, UserDetails {
    private final Long id;
    private final String email;
    private final String password;
    private final UserStatus status;
    private final Collection<? extends GrantedAuthority> authorities;
    private final boolean mfaVerified;
    private Map<String, Object> attributes;

    public UserPrincipal(Long id, String email, String password, UserStatus status, Collection<String> roles, boolean mfaVerified) {
        this.id = id;
        this.email = email;
        this.password = password;
        this.status = status;
        this.authorities = roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
        this.mfaVerified = mfaVerified;
    }

    public UserPrincipal(Long id, String email, String password, UserStatus status, Collection<String> roles, boolean mfaVerified, Map<String, Object> attributes) {
        this(id, email, password, status, roles, mfaVerified);
        this.attributes = attributes;
    }

    public UserPrincipal(Long id, String email, Collection<String> roles, boolean mfaVerified) {
        this.id = id;
        this.email = email;
        this.password = null;
        this.status = UserStatus.ACTIVE;
        this.authorities = roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
        this.mfaVerified = mfaVerified;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.status != UserStatus.LOCKED;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return this.status == UserStatus.ACTIVE;
    }

    @Override
    public String getName() {
        return email;
    }
}
