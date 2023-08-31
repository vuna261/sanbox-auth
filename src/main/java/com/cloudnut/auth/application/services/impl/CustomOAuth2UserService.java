package com.cloudnut.auth.application.services.impl;

import com.cloudnut.auth.application.exception.OAuth2AuthenticationProcessingException;
import com.cloudnut.auth.application.security.user.OAuth2UserInfo;
import com.cloudnut.auth.application.security.user.OAuth2UserInfoFactory;
import com.cloudnut.auth.domain.User.UserPrincipal;
import com.cloudnut.auth.infrastructure.entity.UserEntityDB;
import com.cloudnut.auth.infrastructure.entity.UserRoleEntityDB;
import com.cloudnut.auth.infrastructure.repository.UserEntityRepo;
import com.cloudnut.auth.infrastructure.repository.UserRoleEntityRepo;
import com.cloudnut.auth.utils.Constants;
import com.cloudnut.auth.utils.ProviderUtils;
import com.cloudnut.auth.utils.UserUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    @Autowired
    private UserEntityRepo userEntityRepo;

    @Autowired
    private UserRoleEntityRepo userRoleEntityRepo;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

        try {
            return processOauthUser(oAuth2UserRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOauthUser(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory
                .getOAuth2UserInfo(oAuth2UserRequest.getClientRegistration().getRegistrationId(), oAuth2User.getAttributes());
        if(StringUtils.isEmpty(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }

        ProviderUtils.PROVIDER provider = ProviderUtils.PROVIDER.valueOf(oAuth2UserRequest.
                getClientRegistration().getRegistrationId().toUpperCase());
        Optional<UserEntityDB> userEntityDBOptional = userEntityRepo.findByEmailAndProvider(oAuth2UserInfo.getEmail(), provider);
        UserEntityDB userEntityDB;
        if (userEntityDBOptional.isPresent()) {
            userEntityDB = userEntityDBOptional.get();
            userEntityDB = updateUser(userEntityDB, oAuth2UserInfo);
        } else {
            userEntityDB = registerUser(oAuth2UserRequest, oAuth2UserInfo);
        }

        UserRoleEntityDB userRoleEntityDB = userRoleEntityRepo.findByUserId(userEntityDB.getId());

        List<GrantedAuthority> authorities = UserUtils.buildAuthorityByRole(userRoleEntityDB.getRole());

        return UserPrincipal.builder()
                .id(userEntityDB.getId())
                .email(userEntityDB.getEmail())
                .password(userEntityDB.getPassword())
                .authorities(authorities)
                .attributes(oAuth2UserInfo.getAttributes())
                .build();
    }

    private UserEntityDB registerUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {
        // save user object
        UserEntityDB userEntityDB = UserEntityDB.builder()
                .provider(ProviderUtils.PROVIDER.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId().toUpperCase()))
                .providerId(oAuth2UserInfo.getId())
                .name(oAuth2UserInfo.getName())
                .email(oAuth2UserInfo.getEmail())
                .imageUrl(oAuth2UserInfo.getImageUrl())
                .isActive(true)
                .isDefault(false)
                .emailVerified(false)
                .build();
        userEntityDB = userEntityRepo.save(userEntityDB);

        // save role
        UserRoleEntityDB userRoleEntityDB = UserRoleEntityDB.builder()
                .userId(userEntityDB.getId())
                .role(UserUtils.ROLE.TRAINEE)
                .createdDate(new Date())
                .updatedDate(new Date())
                .createdBy(Constants.SYSTEM)
                .updatedBy(Constants.SYSTEM)
                .build();
        userRoleEntityRepo.save(userRoleEntityDB);

        return userEntityDB;
    }

    private UserEntityDB updateUser(UserEntityDB userEntityDB, OAuth2UserInfo oAuth2UserInfo) {
        userEntityDB.setName(oAuth2UserInfo.getName());
        userEntityDB.setImageUrl(oAuth2UserInfo.getImageUrl());
        return userEntityRepo.save(userEntityDB);
    }
}
