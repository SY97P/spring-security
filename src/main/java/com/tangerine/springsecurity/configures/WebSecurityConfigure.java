package com.tangerine.springsecurity.configures;

import com.tangerine.springsecurity.jwt.Jwt;
import com.tangerine.springsecurity.jwt.JwtAuthenticationFilter;
import com.tangerine.springsecurity.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import com.tangerine.springsecurity.oauth2.OAuth2AuthenticationSuccessHandler;
import com.tangerine.springsecurity.user.UserService;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final ApplicationContext applicationContext;
    private final JwtConfigure jwtConfigure;

    public WebSecurityConfigure(ApplicationContext applicationContext, JwtConfigure jwtConfigure) {
        this.applicationContext = applicationContext;
        this.jwtConfigure = jwtConfigure;
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

    // 정적리소스는 spring security filter 를 걸어주지 않음
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

    public JwtAuthenticationFilter jwtAuthenticationFilter(Jwt jwt) {
        return new JwtAuthenticationFilter(jwtConfigure.getHeader(), jwt);
    }

    @Bean
    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }

    // 원래 OAuth2 인증 서비스는 in-mem 방식
    // 이러면 OAuth2 인증 사용자가 많아질 수록 서버 메모리 소모
    // 서버 장애 시 인증에 장애 발생
    // JDBC 방식의 인증 서비스 사용하도록 설정 변경
    @Bean
    public OAuth2AuthorizedClientService auth2AuthorizedClientService(
            JdbcOperations jdbcOperations,
            ClientRegistrationRepository clientRegistrationRepository
    ) {
        return new JdbcOAuth2AuthorizedClientService(jdbcOperations, clientRegistrationRepository);
    }

    @Bean
    public OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository(
            OAuth2AuthorizedClientService oAuth2AuthorizedClientService
    ) {
        return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(oAuth2AuthorizedClientService);
    }

    @Bean
    public OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler(Jwt jwt, UserService userService) {
        return new OAuth2AuthenticationSuccessHandler(jwt, userService);
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
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(endPoint -> endPoint
                                .authorizationRequestRepository(authorizationRequestRepository()))
                        .authorizedClientRepository(applicationContext.getBean(OAuth2AuthorizedClientRepository.class))
                        .successHandler(oAuth2AuthenticationSuccessHandler(jwt(), applicationContext.getBean(UserService.class))))
                .exceptionHandling(handler -> handler
                        .accessDeniedHandler(accessDeniedHandler()))
                .addFilterAfter(jwtAuthenticationFilter(jwt()), SecurityContextPersistenceFilter.class)
        ;
        return http.build();
    }

}