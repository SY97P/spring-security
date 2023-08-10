package com.tangerine.springsecurity.jwt;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.List;

import static java.util.Collections.emptyList;
import static org.apache.logging.log4j.util.Strings.isNotEmpty;

public class JwtAuthenticationFilter extends GenericFilter {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final String headerKey; // http 헤더에서 jwt 분리할 때 사용
    private final Jwt jwt;          // jwt 객체를 디코딩할 때 사용

    public JwtAuthenticationFilter(String headerKey, Jwt jwt) {
        this.headerKey = headerKey;
        this.jwt = jwt;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            String token = getToken(req);
            if (token != null) {
                try {
                    Jwt.Claims claims = verify(token);
                    log.debug("Jwt parse result: {}", claims);

                    // jwt 에서 loginId(username), roles(GrantedAuthority로 치환) 추출
                    String username = claims.username;
                    List<SimpleGrantedAuthority> authorities = getAuthorities(claims);

                    if (isNotEmpty(username) && !authorities.isEmpty()) {
                        // Jwt에서 추출한 loginId, roles 를 token으로 만들어줌
                        // SecurityContext 에 넣어, 필터로 쓰기 위함
                        JwtAuthenticationToken authentication =
                                new JwtAuthenticationToken(authorities, new JwtAuthentication(token, username), null);
                        // 원격주소, 세션 아이디를 세팅
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
                        // 생성한 UsernamePasswordAuthenticationToken 을 SecurityContext 에 넣어줌
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                } catch (Exception e) {
                    log.warn("Jwt processing failed: {}", e.getMessage());
                }
            }
        } else {
            log.debug(
                    "SecurityContextHolder not populated with security token, as it already contained: '{}'",
                    SecurityContextHolder.getContext().getAuthentication()
            );
        }
        chain.doFilter(req, res);
    }

    @Override
    public void destroy() {
        super.destroy();
    }

    /**
     * HTTP 요청 헤더에서 JWT 토큰 있는지 확인
     */
    private String getToken(HttpServletRequest request) {
        String token = request.getHeader(headerKey);
        if (isNotEmpty(token)) {
            log.debug("Jwt authorization api detected: {}", token);
            try {
                return URLDecoder.decode(token, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                log.error(e.getMessage(), e);
            }
        }
        return null;
    }

    /**
     * jwt 토큰 검사
     * 만료되거나, 변조되면 예외 발생
     */
    private Jwt.Claims verify(String token) {
        return jwt.verify(token);
    }

    private List<SimpleGrantedAuthority> getAuthorities(Jwt.Claims claims) {
        // 권한 -> 인증된 권한
        String[] roles = claims.roles;
        return roles == null || roles.length == 0 ?
                emptyList() :
                Arrays.stream(roles).map(SimpleGrantedAuthority::new).toList();
    }
}
