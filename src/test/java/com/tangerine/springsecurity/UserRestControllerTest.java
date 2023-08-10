package com.tangerine.springsecurity;

import com.tangerine.springsecurity.configures.JwtConfigure;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class UserRestControllerTest {

    @Autowired
    private JwtConfigure jwtConfigure;

    @Autowired
    private TestRestTemplate testRestTemplate;

    @Test
    void JWT_토큰_테스트() {
        assertThat(tokenToName(getToken("user"))).isEqualTo("user");
        assertThat(tokenToName(getToken("admin"))).isEqualTo("admin");
    }

    private String getToken(String username) {
        return testRestTemplate.exchange(
                "/api/user/" + username + "/token",
                HttpMethod.GET,
                null,
                String.class
        ).getBody();
    }

    private String tokenToName(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(jwtConfigure.getHeader(), token);
        return testRestTemplate.exchange(
                "/api/user/me",
                HttpMethod.GET,
                new HttpEntity<>(headers),
                String.class
        ).getBody();
    }

}
