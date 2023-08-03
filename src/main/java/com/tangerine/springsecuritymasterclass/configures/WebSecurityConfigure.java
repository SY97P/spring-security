package com.tangerine.springsecuritymasterclass.configures;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;

import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasRole;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    // HttpSecurity : 세부적인 웹 보안기능 설정 처리 api 제공
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/me").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/admin").hasRole("ADMIN").requestMatchers("/admin").fullyAuthenticated()
                        .anyRequest()
                        .permitAll())
                .formLogin(login -> login
//                        .loginPage("/my-login") // 커스텀 로그인 페이지를 만든 경우
//                        .usernameParameter("my-username")
//                        .passwordParameter("my-password")
                        .defaultSuccessUrl("/login")
                        .permitAll())
                .rememberMe(remember -> remember
                        .rememberMeCookieName("remember-me")
                        .rememberMeParameter("remember-me")
                        .tokenValiditySeconds(300)
                        .alwaysRemember(false))
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                        .logoutSuccessUrl("/")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("remember-me"))
                .requiresChannel(channel -> channel
                        .anyRequest()
//                        .requestMatchers("/api/**")
                        .requiresSecure())
                .exceptionHandling(handler -> handler
                        .accessDeniedHandler(accessDeniedHandler()))
                .sessionManagement(session -> session
                        .sessionFixation().changeSessionId() // 세션 픽세이션 보안 옵션 -> changeSession: 새로운 세션 X, 공격 방어 O
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // 필요시 세션 생성
                        .invalidSessionUrl("/") // 잘못된 session url인 경우 도달하는 url 경로
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false))
        ;
        return http.build();
    }

    // 정적리소스는 spring security filter를 걸어주지 않음
    // *.html, *.css, *.js
    // 불필요한 서버 자원 낭비 방지
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .requestMatchers("/assets/**");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User
                .withUsername("user")
                .password(passwordEncoder.encode("user123"))
                .roles("USER")
                .build());
        manager.createUser(User
                .withUsername("admin")
                .password(passwordEncoder.encode("admin123"))
                .roles("ADMIN")
                .build());
        return manager;
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            logger.warn("{} is denied", principal, accessDeniedException);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain");
            response.getWriter().write("## ACCESS DENIED ##");
            response.getWriter().flush();
            response.getWriter().close();
        };
    }

//    @Bean
//    @Order(0)
//    public SecurityFilterChain resources(HttpSecurity http) throws Exception {
//        return http
//                .authorizeHttpRequests(authz -> authz
//                        .requestMatchers("/assets/**")
//                        .hasAnyRole("USER", "ADMIN")
//                        .anyRequest()
//                        .permitAll())
//                .build();
//    }

}