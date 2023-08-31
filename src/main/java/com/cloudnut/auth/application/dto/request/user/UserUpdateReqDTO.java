package com.cloudnut.auth.application.dto.request.user;

import com.cloudnut.auth.utils.UserUtils;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserUpdateReqDTO {
    private UserUtils.ROLE userRole;
    private Boolean lock;
}
