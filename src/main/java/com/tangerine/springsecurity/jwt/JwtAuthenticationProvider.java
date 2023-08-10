package com.tangerine.springsecurity.jwt;

import com.tangerine.springsecurity.user.User;
import com.tangerine.springsecurity.user.UserService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

/**
 * JwtAuthenticationToken 타입 인증 요청을 처리할 수 있는 Provider
 */
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final UserService userService;
    private final Jwt jwt;

    public JwtAuthenticationProvider(UserService userService, Jwt jwt) {
        this.userService = userService;
        this.jwt = jwt;
    }

    // 인증 처리
    private Authentication processUserAuthentication(String principal, String credentials) {
        try {
            // UserService 를 이용해 로그인 처리 + JWT 토큰 생성
            User user = userService.login(principal, credentials);
            List<SimpleGrantedAuthority> authorities = user.getGroup().getAuthorities();
            String token = getToken(user.getLoginId(), authorities);
            JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(
                    authorities,
                    new JwtAuthentication(token, user.getLoginId()),
                    null
            );
            authenticationToken.setDetails(user);
            return authenticationToken;
        } catch (IllegalArgumentException e) {
            throw new BadCredentialsException(e.getMessage(), e);
        } catch (Exception e) {
            throw new AuthenticationServiceException(e.getMessage(), e);
        }
    }

    private String getToken(String username, List<SimpleGrantedAuthority> authorities) {
        String[] roles = authorities.stream()
                .map(SimpleGrantedAuthority::getAuthority)
                .toArray(String[]::new);
        return jwt.sign(Jwt.Claims.from(username, roles));
    }

    // 인증이 완료된 사용자의 JwtAuthenticationToken 을 반환함
    // - principal 필드 — JwtAuthentication 객체
    // - details 필드 — com.tangerine.springsecurity.user.User 객체 (org.springframework.security.core.userdetails.User와 명백히 다름에 주목)
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;
        return processUserAuthentication(
                String.valueOf(jwtAuthenticationToken.getPrincipal()),
                String.valueOf(jwtAuthenticationToken.getCredentials())
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // JwtAuthenticationToken 타입 인증요청을 처리할 수 있다.
        // 다시말해 파라미터로 주어진 authentication 을 JwtAuthenticationToken 으로 할당 가능하다
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
