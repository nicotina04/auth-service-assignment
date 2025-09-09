package io.assignment.auth.controller;

import io.assignment.auth.api.MeApi;
import io.assignment.auth.dto.User;
import io.assignment.auth.dto.UserStatus;
import io.assignment.auth.dto.UserPrincipal;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.stream.Collectors;

@RestController
public class MeController implements MeApi {

    @Override
    @GetMapping(value = "/me", produces = "application/json")
    public ResponseEntity<User> meGet() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getPrincipal() == null || !(auth.getPrincipal() instanceof UserPrincipal principal)) {
            return ResponseEntity.status(401).build();
        }

        var roles = principal.getAuthorities().stream()
                .map(a -> a.getAuthority())
                .collect(Collectors.toList());

        var dto = new User()
                .id(principal.getId())
                .email(principal.getEmail())
                .status(UserStatus.fromValue(principal.getStatus().name()))
                .roles(roles);

        return ResponseEntity.ok(dto);
    }

    @Override
    @GetMapping("/me/sessions")
    public ResponseEntity<Void> meSessionsGet() {
        return ResponseEntity.ok().build();
    }
}
