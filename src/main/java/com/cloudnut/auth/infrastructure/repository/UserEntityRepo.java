package com.cloudnut.auth.infrastructure.repository;

import com.cloudnut.auth.infrastructure.entity.UserEntityDB;
import com.cloudnut.auth.utils.ProviderUtils;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.repository.PagingAndSortingRepository;

import java.util.Optional;

public interface UserEntityRepo extends PagingAndSortingRepository<UserEntityDB, Long>,
        JpaSpecificationExecutor<UserEntityDB> {
    Optional<UserEntityDB> findByEmailContainingIgnoreCaseAndProvider(String email, ProviderUtils.PROVIDER provider);
    Optional<UserEntityDB> findById(Long id);
    Optional<UserEntityDB> findByEmail(String email);
    Optional<UserEntityDB> findByEmailAndProvider(String email, ProviderUtils.PROVIDER provider);
    Optional<UserEntityDB> findByVerifyCode(String verifyCode);
    Page<UserEntityDB> findByEmailContainingIgnoreCaseOrNameContainingIgnoreCase(String email, String userName, Pageable pageable);
}
