package io.assignment.auth.config;

import io.assignment.auth.dto.UserPrincipal;
import io.assignment.auth.service.CustomOAuth2UserService;
import io.assignment.auth.token.JwtAuthFilter;
import io.assignment.auth.token.OAuth2LoginSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpMethod;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.Set;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
    private final JwtAuthFilter jwtAuthFilter;
    private final RestAuthenticationEntryPoint restAuthenticationEntryPoint;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter, RestAuthenticationEntryPoint restAuthenticationEntryPoint) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.restAuthenticationEntryPoint = restAuthenticationEntryPoint;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    SecurityFilterChain api(HttpSecurity http,
                            UserDetailsService userDetailsService,
                            PasswordEncoder passwordEncoder,
                            @Lazy CustomOAuth2UserService customOAuth2UserService,
                            @Lazy OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.formLogin(AbstractHttpConfigurer::disable);
        http.httpBasic(AbstractHttpConfigurer::disable);

        http.exceptionHandling(e -> e.authenticationEntryPoint(restAuthenticationEntryPoint));

        http.oauth2Login(oauth2 -> oauth2
                .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
                .successHandler(oAuth2LoginSuccessHandler)
        );

         http.addFilterBefore(jwtAuthFilter, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);

        http.authenticationProvider(authenticationProvider(userDetailsService, passwordEncoder));

        
        http.authorizeHttpRequests(reg -> reg
                .requestMatchers(HttpMethod.POST, "/auth/signup", "/auth/login", "/auth/refresh").permitAll()
                .requestMatchers("/", "/index.html", "/.well-known/jwks.json", "/openapi.yaml").permitAll()
                .requestMatchers("/v3/api-docs/**", "/swagger-ui/**").permitAll()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                .requestMatchers("/login/oauth2/code/**", "/oauth2/authorization/**").permitAll()
                .requestMatchers("/admin/**").access(mfaRequired(Set.of("MASTER", "ADMIN")))
                .requestMatchers("/master/**").access(mfaRequired(Set.of("MASTER")))
                .requestMatchers("/parent/**").hasAnyRole("PARENT", "ADMIN", "MASTER")
                .anyRequest().authenticated());

        return http.build();
    }


    private AuthorizationManager<RequestAuthorizationContext> mfaRequired(Set<String> allowedRoles) {
        return ((authentication, object) -> {
            var auth = authentication.get();
            if (auth == null || auth.getPrincipal() == null) {
                return new AuthorizationDecision(false);
            }
            var principal = (UserPrincipal)auth.getPrincipal();
            var roleOk = principal.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .anyMatch(allowedRoles::contains);
            var mfaOk = principal.isMfaVerified();

            return new AuthorizationDecision(roleOk && mfaOk);
        });
    }

}
