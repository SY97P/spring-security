package com.tangerine.springsecurity.user;

import java.util.StringJoiner;

public class UserDto {

    private final String token;
    private final String username;
    private final String group;

    public UserDto(String token, String username, String group) {
        this.token = token;
        this.username = username;
        this.group = group;
    }

    public String getToken() {
        return token;
    }

    public String getUsername() {
        return username;
    }

    public String getGroup() {
        return group;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", UserDto.class.getSimpleName() + "[", "]")
                .add("token='" + token + "'")
                .add("username='" + username + "'")
                .add("group='" + group + "'")
                .toString();
    }

}
