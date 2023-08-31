package com.cloudnut.auth.application.dto.response.user;

import com.cloudnut.auth.utils.ProviderUtils;
import com.cloudnut.auth.utils.UserUtils;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserResDTO {
    private Long id;
    private String email;
    private String name;
    private ProviderUtils.PROVIDER provider;
    private Boolean isActive;
    private UserUtils.ROLE role;
}
