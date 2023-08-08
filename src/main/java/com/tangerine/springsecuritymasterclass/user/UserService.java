package com.tangerine.springsecuritymasterclass.user;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class UserService implements UserDetailsService {

    private final UserRepository repository;

    public UserService(UserRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return repository.findByLoginId(username)
                .map(user ->
                    /*
                      여기서 반환해야 하는 User 는 우리가 만든 User 가 아니라,
                      UserDetails 의 User 임
                     */
                    User.builder()
                            .username(user.getLoginId())
                            .password(user.getPasswd())
                            .authorities(user.getGroup().getAuthorities())
                            .build()
                )
                .orElseThrow(() -> new UsernameNotFoundException("Could not found user for " + username));
    }
}
