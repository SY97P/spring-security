# Spring Security Mission

## #1. 1일차 미션

### 기본 로그인 계정 추가

```java
@Bean
UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
    InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
    manager.createUser(User
            .withUsername("user")
            .password(passwordEncoder.encode("user123"))
            .roles("USER")
            .build());
    manager.createUser(User
            .withUsername("admin")
            .password(passwordEncoder.encode("admin123"))
            .roles("ADMIN")
            .build());
    return manager;
}
```

### 비밀번호 암호화

- Spring Security 5 부터 `DelegatingPasswordEncoder` 클래스가 기본 `PasswordEncoder`.
- `DelegatingPasswordEncoder` 클래스 안에 비밀번호 해시 알고리즘 별로 Map에 저장
  - `bcrypt`, `noop`, `sha256`, etc
  - 해시 알고리즘 별 `PasswordEncoder` 선택 위해 패스워드 앞에 prefix 추가
    - {bcrypt}....
    - {noop}password
    - {pbkdf2}...
    - {sha256}...
  - prefix 생략되는 경우 기본값 bcrypt 인코더 선택
- `DelegatingPasswordEncoder` 말고 세부 `PasswordEncoder`를 `Bean`으로 등록해도 됨.
  - `BcryptPasswordEncoder` 를 `Bean`으로 등록
- password 업그레이드
  - 비밀번호 해시 알고리즘 변경 시 강력한 해시 알고리즘으로 업그레이드
  - `InMemoryUserDetailsManager` 객체 사용 시 로그인 최초 1회 성공 시 {noop} 에서 {bcrypt}로 encoder 업그레이드
```java
@Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
```

### 로그아웃 기능 설정

- `LogoutFilter`
- `SecurityFilterChain` 에 필터 추가
```java
HttpSecurity http;
http.logout(logout -> logout
        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
        .logoutSuccessUrl("/")
        .invalidateHttpSession(true)
        .clearAuthentication(true)
        .deleteCookies("remember-me"))
```

### 쿠키 기반 자동 로그인

- `RememberMeAuthenticationFilter`
- `SecurityFilterChain` 에 필터 추가
```java
HttpSecurity http;
http.rememberMe(remember -> remember
        .rememberMeCookieName("remember-me")
        .rememberMeParameter("remember-me")
        .tokenValiditySeconds(300)
        .alwaysRemember(false))
```

<hr/>

## #2. 2일차 미션

### Security Filter 정리

#### `AnonymousAuthenticationFilter`
- 해당 인증 필터에 도달할 때까지 사용자가 인증 미완(사용자 = null)이면, 익명 사용자로 처리
- `SecurityContextHolder` 에 인증 개체가 없는지 감지하고 필요한 경우 하나로 채웁니다.

#### `ExceptionTranslationFilter`
- 요청 처리 도중 발생 가능한 예외에 대한 라우팅, 위임 처리
- 필터 체인 내에서 발생한 모든 `AccessDeniedException` 및 `AuthenticationException`을 처리.
- Java 예외와 HTTP 응답 간의 브리지를 제공.
- 사용자 인터페이스 유지 관리에만 관심. 
- 실제 보안 적용을 수행하지 않음. 
- `AuthenticationException`이 감지되면 필터는 `authenticationEntryPoint`를 실행. 
- `AbstractSecurityInterceptor`의 하위 클래스에서 발생하는 인증 실패의 일반적인 처리가 가능. 
- `AccessDeniedException`이 감지되면 필터는 사용자가 익명 사용자인지 여부를 결정.
  - 익명 사용자인 경우 `authenticationEntryPoint`가 시작됩니다. 
  - 익명 사용자가 아닌 경우 필터는 `AccessDeniedHandler`에 위임합니다. 
- 기본적으로 필터는 `AccessDeniedHandlerImpl`을 사용합니다. 
- 이 필터를 사용하려면 다음 속성을 지정해야 합니다. `authenticationEntryPoint`는 `AuthenticationException`이 감지된 경우 인증 프로세스를 시작해야 하는 핸들러를 나타냅니다. 
- SSL 로그인을 위해 현재 프로토콜을 http에서 https로 전환할 수도 있습니다. 
- `requestCache`는 사용자가 인증한 후에 요청을 검색하고 재사용할 수 있도록 인증 프로세스 중에 요청을 저장하는 데 사용되는 전략을 결정합니다. 
- 기본 구현은 `HttpSessionRequestCache`입니다.
#### AccessDeniedException 예외에 대한 핸들러 설정이 가능함
- 기본 구현은 org.springframework.security.web.access.AccessDeniedHandlerImpl 클래스
- HttpSecurity  클래스의 exceptionHandling() 메소드를 통해 사용자 정의 핸들러를 설정함
    - 접근 거부 요청에 대한 로깅 처리
    - HTTP 403 응답 생성

### 대칭키 암호화, RSA 암호화

#### 대칭키 암호화
- 송/수신 똑같은 키
- 암호화, 복호화에 같은 키 사용 (대칭키)
- 대칭키를 안전하게 교환하는 게 중요

#### 비대칭키 암호화
- 암호화, 복호화에 다른 키 사용
- 공개키
  - 공개된 키
  - 암복호화에 사용
- 개인키
  - 나만 아는 키
  - 암복호화에 사용
1. 공개키로 암호화하는 경우
   - 복호화는 개인키
   - 특정 사용자에게 보내는 경우
   - 컨텐츠 보호가 중요한 경우
2. 개인키로 암호화하는 경우
   - 복호화는 공개키
   - 수신자가 중요한 경우 (공개키로 열리면 -> 아! 누구누구구나!)
   - 정보 생상자 신원 정보가 중요한 경우

#### RSA 암호화
- 비대칭키 암호화에서 사용
- 서버 개인키로 암호화 + 클라가 서버 공개키로 복호화 시 필요
- 주고받는 http 메시지 보호를 위해서 RSA 필요
- '큰 수의 인수분해는 어렵다'