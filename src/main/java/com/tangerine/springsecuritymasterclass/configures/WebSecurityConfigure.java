package com.tangerine.springsecuritymasterclass.configures;

import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final DataSource dataSource;

    public WebSecurityConfigure(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    // HttpSecurity : 세부적인 웹 보안기능 설정 처리 api 제공
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(AntPathRequestMatcher.antMatcher("/me")).hasAnyRole("USER", "ADMIN")
                        .requestMatchers(AntPathRequestMatcher.antMatcher("/admin")).hasRole("ADMIN")
                        .requestMatchers(AntPathRequestMatcher.antMatcher("/admin")).fullyAuthenticated()
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
                .requestMatchers(
                        AntPathRequestMatcher.antMatcher("/assets/**"),
                        AntPathRequestMatcher.antMatcher("/h2-console/**")
                );
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        JdbcDaoImpl jdbcDao = new JdbcDaoImpl();
        jdbcDao.setDataSource(dataSource);
        jdbcDao.setEnableAuthorities(false);
        jdbcDao.setEnableGroups(true);
        jdbcDao.setUsersByUsernameQuery(
                """
                SELECT login_id, passwd, true
                    FROM users
                    WHERE login_id = ?
                """
        );
        jdbcDao.setGroupAuthoritiesByUsernameQuery(
                """
                SELECT u.login_id, g.name, p.name
                    FROM users u
                    JOIN groups g ON u.group_id = g.id
                    LEFT JOIN group_permission gp ON g.id = gp.group_id
                    JOIN permissions p ON p.id = gp.permission_id
                    WHERE u.login_id = ?
                """
        );
        return jdbcDao;
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

}