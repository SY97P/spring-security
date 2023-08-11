package com.tangerine.springsecurity.user;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

import static io.micrometer.common.util.StringUtils.isNotEmpty;
import static org.h2.mvstore.DataUtils.checkArgument;

@Service
@Transactional(readOnly = true)
public class UserService {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final UserRepository userRepository;
    private final GroupRepository groupRepository;

    public UserService(UserRepository userRepository, GroupRepository groupRepository) {
        this.userRepository = userRepository;
        this.groupRepository = groupRepository;
    }

    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username) {
        checkArgument(isNotEmpty(username), "username must be provided");

        return userRepository.findByUsername(username);
    }

    @Transactional(readOnly = true)
    public Optional<User> findByProviderAndProviderId(String provider, String providerId) {
        checkArgument(isNotEmpty(provider), "provider must be provided");
        checkArgument(isNotEmpty(providerId), "providerId must be provided");

        return userRepository.findByProviderAndProviderId(provider, providerId);
    }

    @Transactional
    public User join(OAuth2User oAuth2User, String provider) {
        checkArgument(oAuth2User != null, "oauth2User must be provided");
        checkArgument(isNotEmpty(provider), "provider must be provided");

        /*
          username - 카카오 닉네임
          provider - 파라미터
          providerId - oauth2User.getName()
          profileImage - 카카오 인증된 사용자의 프로필 이미지 사용
          group - USER_GROUP Group
         */
        String providerId = oAuth2User.getName();
        return findByProviderAndProviderId(provider, providerId)
                .map(user -> {
                    log.warn("Already exists: {} for provider: {} providerId: {}", user, provider, providerId);
                    return user;
                })
                .orElseGet(() -> {
                    Map<String, Object> attributes = oAuth2User.getAttributes();
                    Map<String, Object> properties = (Map<String, Object>) attributes.get("properties");
                    checkArgument(properties != null, "OAuth2User properties is empty");

                    String nickname = (String) properties.get("nickname");
                    String profileImage = (String) properties.get("profile_image");
                    Group group = groupRepository.findByName("USER_GROUP")
                            .orElseThrow(() -> new IllegalArgumentException("Could not found group for USER_GROUP"));
                    return userRepository.save(
                            new User(nickname, provider, providerId, profileImage, group)
                    );
                });
    }

}
