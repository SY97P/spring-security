package com.tangerine.springsecurity.jwt;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.tangerine.springsecurity.user.User;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.StringJoiner;

import static org.apache.logging.log4j.util.Strings.isNotEmpty;

public class JwtAuthentication {

    private final String token;
    private final String username;

    public JwtAuthentication(String token, String username) {
        Assert.notNull(token, "token must be provided");
        Assert.notNull(username, "username must be provided");

        this.token = token;
        this.username = username;
    }

    public String getToken() {
        return token;
    }

    public String getUsername() {
        return username;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", JwtAuthentication.class.getSimpleName() + "[", "]")
                .add("token='" + token + "'")
                .add("username='" + username + "'")
                .toString();
    }
}
