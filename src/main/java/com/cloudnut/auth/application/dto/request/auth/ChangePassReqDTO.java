package com.cloudnut.auth.application.dto.request.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ChangePassReqDTO {
    @NotBlank
    private String oldPass;

    @NotBlank
    private String newPass;
}
