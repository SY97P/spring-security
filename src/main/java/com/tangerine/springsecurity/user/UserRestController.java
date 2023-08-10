package com.tangerine.springsecurity.user;

import com.tangerine.springsecurity.jwt.JwtAuthentication;
import com.tangerine.springsecurity.jwt.JwtAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

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

    // @AuthenticationPrincipal
    // authentication 구현체에서 principal 부분을 추출해서 컨트롤러로 넘겨주는 역할
    // JwtAuthentication 이 Authentication 을 상속하고, JwtAuthentication 의 principal 로 JwtAuthenticationToken 을 주었기 때문
    @GetMapping(path = "/user/me")
    public UserDto me(@AuthenticationPrincipal JwtAuthentication authentication) {
        return service.findByLoginId(authentication.getUsername())
                .map(user -> new UserDto(authentication.getToken(), authentication.getUsername(), user.getGroup().getName()))
                .orElseThrow(() -> new IllegalArgumentException("Could not found user for " + authentication.getUsername()));
    }

}