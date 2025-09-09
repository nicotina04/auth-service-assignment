package io.assignment.auth.service;

import io.assignment.auth.domain.Role;
import io.assignment.auth.domain.User;
import io.assignment.auth.domain.UserRole;
import io.assignment.auth.domain.UserStatus;
import io.assignment.auth.dto.UserPrincipal;
import io.assignment.auth.repository.UserRepository;
import io.assignment.auth.repository.UserRoleRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        Map<String, Object> attributes = oAuth2User.getAttributes();
        String email = (String) attributes.get("email");

        
        User user = userRepository.findByEmailIgnoreCase(email)
                .orElseGet(() -> createNewUser(email));

        List<String> roles = userRoleRepository.findRoleNamesByUserId(user.getId());

        
        return new UserPrincipal(user.getId(), user.getEmail(), null, user.getStatus(), roles, true, attributes);
    }

    private User createNewUser(String email) {
        var user = new User();
        user.setEmail(email);
        // Social accounts do not use local credentials; set a random encoded placeholder to satisfy NOT NULL.
        user.setPasswordHash(passwordEncoder.encode("oauth2:" + java.util.UUID.randomUUID()));
        user.setStatus(UserStatus.ACTIVE);
        user.setMfaEnabled(false);
        user.setCreatedAt(OffsetDateTime.now());
        user.setUpdatedAt(OffsetDateTime.now());
        userRepository.save(user);

        
        var userRole = new UserRole(user.getId(), Role.PARENT);
        userRoleRepository.save(userRole);

        return user;
    }
}
