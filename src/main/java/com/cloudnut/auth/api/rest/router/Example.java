package com.cloudnut.auth.api.rest.router;

import com.cloudnut.auth.api.rest.factory.response.ResponseFactory;
import com.cloudnut.auth.application.constant.ResponseStatusCodeEnum;
import com.cloudnut.auth.application.dto.response.common.GeneralResponse;
import com.cloudnut.auth.application.exception.BaseResponseException;
import com.cloudnut.auth.utils.FileUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.PrivateKey;
import java.security.PublicKey;

@RestController
@RequestMapping("${app.base-url}/example")
@Slf4j
public class Example {
    @Autowired
    ResponseFactory responseFactory;

    @GetMapping("/private")
    public ResponseEntity<GeneralResponse<String>> getPrivate() {
        String token;
        try {
            PrivateKey privateKey = FileUtils.getPrivateKeyFromFile("private_key_pkcs8.pem");
            token = privateKey.toString();
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new BaseResponseException(ResponseStatusCodeEnum.BUSINESS_ERROR);
        }
        return responseFactory.success(token);
    }

    @GetMapping("/public")
    public ResponseEntity<GeneralResponse<String>> getPublic() {
        String token;
        try {
            PublicKey privateKey = FileUtils.getPublicKeyFromFile("public_key.pem");
            token = new String(privateKey.toString());
        } catch (Exception e) {
            throw new BaseResponseException(ResponseStatusCodeEnum.BUSINESS_ERROR);
        }
        return responseFactory.success(token);
    }
}
