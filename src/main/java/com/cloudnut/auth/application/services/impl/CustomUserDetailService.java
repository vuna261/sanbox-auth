package com.cloudnut.auth.application.services.impl;

import com.cloudnut.auth.domain.User.UserPrincipal;
import com.cloudnut.auth.infrastructure.entity.UserEntityDB;
import com.cloudnut.auth.infrastructure.entity.UserRoleEntityDB;
import com.cloudnut.auth.infrastructure.repository.UserEntityRepo;
import com.cloudnut.auth.infrastructure.repository.UserRoleEntityRepo;
import com.cloudnut.auth.utils.ProviderUtils;
import com.cloudnut.auth.utils.UserUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;
import java.util.Optional;

@Service
public class CustomUserDetailService implements UserDetailsService {
    @Autowired
    UserEntityRepo userEntityRepo;

    @Autowired
    UserRoleEntityRepo userRoleEntityRepo;

    /**
     * load user detail by username
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UserEntityDB> entityDBOptional = userEntityRepo.findByEmailAndProvider(username, ProviderUtils.PROVIDER.LOCAL);
        if (!entityDBOptional.isPresent()) {
            throw new UsernameNotFoundException("User not found");
        }
        UserEntityDB userEntityDB = entityDBOptional.get();
        return buildUserDetailByEntity(userEntityDB);
    }

    /**
     * load user detail by id
     * @param id
     * @return
     * @throws UsernameNotFoundException
     */
    @Transactional
    public UserDetails loadUserById(Long id) throws UsernameNotFoundException {
        Optional<UserEntityDB> entityDBOptional = userEntityRepo.findById(id);
        if (!entityDBOptional.isPresent()) {
            throw new UsernameNotFoundException("User not found");
        }
        UserEntityDB userEntityDB = entityDBOptional.get();
        return buildUserDetailByEntity(userEntityDB);
    }

    /**
     * build user detail by entity
     * @param userEntityDB
     * @return
     */
    private UserDetails buildUserDetailByEntity(UserEntityDB userEntityDB) {
        UserRoleEntityDB userRoleEntityDB = userRoleEntityRepo.findByUserId(userEntityDB.getId());

        List<GrantedAuthority> authorities = UserUtils.buildAuthorityByRole(userRoleEntityDB.getRole());
        return UserPrincipal.builder()
                .id(userEntityDB.getId())
                .email(userEntityDB.getEmail())
                .password(userEntityDB.getPassword())
                .authorities(authorities)
                .build();
    }
}
