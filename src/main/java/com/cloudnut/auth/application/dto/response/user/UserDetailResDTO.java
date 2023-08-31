package com.cloudnut.auth.application.dto.response.user;

import com.cloudnut.auth.utils.UserUtils;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserDetailResDTO {
    private Long id;
    private String email;
    private String name;
    private String imageUrl;
    private UserUtils.ROLE role;
}
