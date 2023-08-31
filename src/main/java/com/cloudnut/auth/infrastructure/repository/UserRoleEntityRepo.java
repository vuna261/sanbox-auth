package com.cloudnut.auth.infrastructure.repository;

import com.cloudnut.auth.infrastructure.entity.UserRoleEntityDB;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface UserRoleEntityRepo extends PagingAndSortingRepository<UserRoleEntityDB, Long>,
        JpaSpecificationExecutor<UserRoleEntityDB> {
    UserRoleEntityDB findByUserId(Long userId);
}
