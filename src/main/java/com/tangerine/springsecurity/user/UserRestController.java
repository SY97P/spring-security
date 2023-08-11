package com.tangerine.springsecurity.user;

import com.tangerine.springsecurity.jwt.JwtAuthentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class UserRestController {

    private final UserService service;

    public UserRestController(UserService service) {
        this.service = service;
    }

    @GetMapping(path = "/user/me")
    public UserDto me(@AuthenticationPrincipal JwtAuthentication authentication) {
        return service.findByUsername(authentication.username)
                .map(user -> new UserDto(authentication.token, authentication.username, user.getGroup().getName()))
                .orElseThrow(() -> new IllegalArgumentException("Could not found user for " + authentication.username));
    }

}