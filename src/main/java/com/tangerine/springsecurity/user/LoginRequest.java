package com.tangerine.springsecurity.user;

import java.util.StringJoiner;

public class LoginRequest {

    private String principal;
    private String credentials;

    protected LoginRequest() {
    }

    public LoginRequest(String principal, String credentials) {
        this.principal = principal;
        this.credentials = credentials;
    }

    public String getPrincipal() {
        return principal;
    }

    public String getCredentials() {
        return credentials;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", LoginRequest.class.getSimpleName() + "[", "]")
                .add("principal='" + principal + "'")
                .add("credentials='" + credentials + "'")
                .toString();
    }
}
