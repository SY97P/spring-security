package com.tangerine.springsecurity.user;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository repository, PasswordEncoder passwordEncoder) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional(readOnly = true)
    public User login(String username, String credentials) {
        User user = repository.findByLoginId(username)
                .orElseThrow(() -> new UsernameNotFoundException("Could not found user for " + username));
        user.checkPassword(passwordEncoder, credentials);
        return user;
    }

}
