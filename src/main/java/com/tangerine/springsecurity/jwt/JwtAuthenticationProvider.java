package com.tangerine.springsecurity.jwt;

import com.tangerine.springsecurity.user.User;
import com.tangerine.springsecurity.user.UserService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
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

    private Authentication processUserAuthentication(String principal, String credentials) {
        try {
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
