package com.tangerine.springsecurity.oauth2;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.SerializationUtils;
import org.springframework.web.util.WebUtils;

import java.util.Base64;
import java.util.Optional;

/**
 * 원래 OAuth2 요청 레포지토리가 Session 기반이라 stateful 함.
 * 이걸 cookie 기반 stateless 로 만들어주기 위해서 하나 커스텀
 */
public class HttpCookieOAuth2AuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    private static final String OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME = "OAUTH2_AUTHORIZATION_REQUEST";

    private final String cookieName;
    private final int cookieExpireSeconds;

    public HttpCookieOAuth2AuthorizationRequestRepository() {
        this(OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME, 180);
    }

    public HttpCookieOAuth2AuthorizationRequestRepository(String cookieName, int cookieExpireSeconds) {
        this.cookieName = cookieName;
        this.cookieExpireSeconds = cookieExpireSeconds;
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        return getCookie(request)
                .map(this::getOAuth2AuthorizationRequest)
                .orElse(null);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        if (authorizationRequest == null) {
            getCookie(request).ifPresent(cookie -> clear(cookie, response));
        } else {
            String value = Base64.getUrlEncoder().encodeToString(SerializationUtils.serialize(authorizationRequest));
            Cookie cookie = new Cookie(cookieName, value);
            cookie.setPath("/");
            cookie.setHttpOnly(true);
            cookie.setMaxAge(cookieExpireSeconds);
            response.addCookie(cookie);
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        return getCookie(request)
                .map(cookie -> {
                    OAuth2AuthorizationRequest oauth2Request = getOAuth2AuthorizationRequest(cookie);
                    clear(cookie, response);
                    return oauth2Request;
                })
                .orElse(null);
    }

    private Optional<Cookie> getCookie(HttpServletRequest request) {
        return Optional.ofNullable(WebUtils.getCookie(request, cookieName));
    }

    private void clear(Cookie cookie, HttpServletResponse response) {
        cookie.setValue("");
        cookie.setPath("");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    private OAuth2AuthorizationRequest getOAuth2AuthorizationRequest(Cookie cookie) {
        return (OAuth2AuthorizationRequest) SerializationUtils.deserialize(
                Base64.getUrlDecoder().decode(cookie.getValue())
        );
    }

}