package com.tangerine.springsecuritymasterclass.configures;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationEventHandler {

    private final Logger logger = LoggerFactory.getLogger(CustomAuthenticationEventHandler.class);

    // 인증 성공 이벤트 리스너
    @EventListener
    public void handleAuthenticationSuccessEvent(AuthenticationSuccessEvent event) {
        Authentication authentication = event.getAuthentication();
        logger.info("Successful authentication result: {}", authentication.getPrincipal());
    }

    // 인증 실패 이벤트 리스너
    @EventListener
    public void handleAuthenticationFailureEvent(AbstractAuthenticationFailureEvent event) {
        Exception e = event.getException();
        Authentication authentication = event.getAuthentication();
        logger.warn("Unsuccessful authentication result: {}", authentication, e);
    }

}
