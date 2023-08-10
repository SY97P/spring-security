package com.tangerine.springsecurity.user;

import com.tangerine.springsecurity.jwt.JwtAuthentication;
import com.tangerine.springsecurity.jwt.JwtAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class UserRestController {

    private final UserService service;
    private final AuthenticationManager authenticationManager;

    public UserRestController(UserService service, AuthenticationManager authenticationManager) {
        this.service = service;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping(path = "/user/login")
    public UserDto login(@RequestBody LoginRequest request) {
        JwtAuthenticationToken token = new JwtAuthenticationToken(request.getPrincipal(), request.getCredentials());
        Authentication resultToken = authenticationManager.authenticate(token);
        JwtAuthenticationToken authenticatedToken = (JwtAuthenticationToken) resultToken;
        JwtAuthentication principal = (JwtAuthentication) authenticatedToken.getPrincipal();
        User user = (User) authenticatedToken.getDetails();
        return new UserDto(principal.getToken(), principal.getUsername(), user.getGroup().getName());
    }

}