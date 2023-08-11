package com.tangerine.springsecurity.jwt;

import java.util.StringJoiner;

import static io.micrometer.common.util.StringUtils.isNotEmpty;
import static org.h2.mvstore.DataUtils.checkArgument;

public class JwtAuthentication {

    public final String token;

    public final String username;

    JwtAuthentication(String token, String username) {
        checkArgument(isNotEmpty(token), "token must be provided.");
        checkArgument(isNotEmpty(username), "username must be provided.");

        this.token = token;
        this.username = username;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", JwtAuthentication.class.getSimpleName() + "[", "]")
                .add("token='" + token + "'")
                .add("username='" + username + "'")
                .toString();
    }
}
