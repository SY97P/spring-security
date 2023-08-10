package com.tangerine.springsecurity.configures;

import com.tangerine.springsecurity.jwt.Jwt;
import com.tangerine.springsecurity.jwt.JwtAuthenticationFilter;
import com.tangerine.springsecurity.jwt.JwtAuthenticationProvider;
import com.tangerine.springsecurity.user.UserService;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final JwtConfigure jwtConfigure;

    public WebSecurityConfigure(JwtConfigure jwtConfigure) {
        this.jwtConfigure = jwtConfigure;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            logger.warn("{} is denied", principal, accessDeniedException);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("## ACCESS DENIED ##");
            response.getWriter().flush();
            response.getWriter().close();
        };
    }

    // 정적리소스는 spring security filter를 걸어주지 않음
    // *.html, *.css, *.js
    // 불필요한 서버 자원 낭비 방지
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .requestMatchers(
                        AntPathRequestMatcher.antMatcher("/assets/**"),
                        AntPathRequestMatcher.antMatcher("/h2-console/**")
                );
    }

    @Bean
    public Jwt jwt() {
        return new Jwt(
                jwtConfigure.getIssuer(),
                jwtConfigure.getClientSecret(),
                jwtConfigure.getExpirySeconds()
        );
    }

    @Bean
    public JwtAuthenticationProvider jwtAuthenticationProvider(Jwt jwt, UserService userService) {
        return new JwtAuthenticationProvider(userService, jwt);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        Jwt jwt = jwt();
        return new JwtAuthenticationFilter(jwtConfigure.getHeader(), jwt);
    }

    // HttpSecurity : 세부적인 웹 보안기능 설정 처리 api 제공
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(AntPathRequestMatcher.antMatcher("/api/user/me")).hasAnyRole("USER", "ADMIN")
                        .anyRequest()
                        .permitAll())
                .csrf(AbstractHttpConfigurer::disable)
                .headers(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .rememberMe(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .exceptionHandling(handler -> handler
                        .accessDeniedHandler(accessDeniedHandler()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterAfter(jwtAuthenticationFilter(), SecurityContextPersistenceFilter.class) // Jwt 필터를 SpringSecurity 필터 체인에 추가
        ;
        return http.build();
    }

}