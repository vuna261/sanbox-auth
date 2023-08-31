package com.cloudnut.auth.api.rest.router;

import com.cloudnut.auth.api.rest.factory.response.ResponseFactory;
import com.cloudnut.auth.application.constant.ResponseStatusCodeEnum;
import com.cloudnut.auth.application.dto.request.auth.ChangePassReqDTO;
import com.cloudnut.auth.application.dto.request.user.UserSignInReqDTO;
import com.cloudnut.auth.application.dto.request.user.UserSignUpReqDTO;
import com.cloudnut.auth.application.dto.response.common.GeneralResponse;
import com.cloudnut.auth.application.dto.response.user.UserTokenResDTO;
import com.cloudnut.auth.application.exception.AuthenticationException;
import com.cloudnut.auth.application.exception.BaseResponseException;
import com.cloudnut.auth.application.exception.UserException;
import com.cloudnut.auth.application.services.interfaces.IAuthService;
import com.cloudnut.auth.application.services.interfaces.IUserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@RestController
@RequestMapping("${app.base-url}")
@Slf4j
public class AuthController {

    @Value("${jwt.verify_url_redirect}")
    private String VERIFY_URL;

    @Autowired
    private IUserService userService;

    @Autowired
    private IAuthService authService;

    @Autowired
    private ResponseFactory responseFactory;

    /**
     * signup new local user
     * @param signUpReqDTO
     * @return
     */
    @PostMapping("/signup")
    public ResponseEntity<GeneralResponse<Object>> signUp(
            @RequestBody @Valid UserSignUpReqDTO signUpReqDTO
    ) {
        try {
            authService.signUp(signUpReqDTO);
        } catch (UserException.AlreadyExisted alreadyExisted) {
            throw new BaseResponseException(ResponseStatusCodeEnum.USER_ALREADY_EXISTED);
        } catch (UnsupportedEncodingException e) {
            throw new BaseResponseException(ResponseStatusCodeEnum.GEN_TOKEN_EXCEPTION);
        } catch (MessagingException e) {
            log.error(e.getMessage());
            throw new BaseResponseException(ResponseStatusCodeEnum.BUSINESS_ERROR);
        }
        return responseFactory.success(new GeneralResponse<>());
    }

    /**
     * login local user
     * @param signInReqDTO
     * @return
     */
    @PostMapping("/login")
    public ResponseEntity<GeneralResponse<UserTokenResDTO>> signIn(
            @RequestBody @Valid UserSignInReqDTO signInReqDTO
    ) {
        UserTokenResDTO userTokenResDTO;
        try {
            userTokenResDTO = userService.signIn(signInReqDTO);
        } catch (UserException.CredentialError credentialError) {
            throw new BaseResponseException(ResponseStatusCodeEnum.CREDENTIAL_ERROR);
        } catch (UserException.UserLocked credentialError) {
            throw new BaseResponseException(ResponseStatusCodeEnum.USER_LOCKED);
        } catch (UserException.UserNotVerify credentialError) {
            throw new BaseResponseException(ResponseStatusCodeEnum.USER_NOT_VERIFY);
        } catch (Exception e) {
            log.error(e.getMessage());
            throw new BaseResponseException(ResponseStatusCodeEnum.BUSINESS_ERROR);
        }
        return responseFactory.success(userTokenResDTO);
    }

    /**
     * verify email
     * @param response
     * @param verifyCode
     * @throws IOException
     */
    @GetMapping("/verify")
    public void verifyEmail(
            HttpServletResponse response,
            @RequestParam(value = "code", required = false, defaultValue = "") String verifyCode
    ) throws IOException {
        try {
            userService.verifyEmail(verifyCode);
        } catch (UserException.NotFound notFound) {
            throw new BaseResponseException(ResponseStatusCodeEnum.USER_NOT_FOUND);
        }
        response.sendRedirect(VERIFY_URL);
    }

    /**
     * forgot password
     * @param email
     * @return
     */
    @GetMapping("/forgot-password")
    public ResponseEntity<GeneralResponse<Object>> forgotPasword(
            @RequestParam(value = "email", required = false, defaultValue = "") String email
    ) {
        try {
            userService.forgotPassword(email);
        } catch (UserException.NotFound notFound) {
            throw new BaseResponseException(ResponseStatusCodeEnum.USER_NOT_FOUND);
        } catch (Exception e) {
            log.error(e.getMessage());
            throw new BaseResponseException(ResponseStatusCodeEnum.BUSINESS_ERROR);
        }
        return responseFactory.success(new GeneralResponse<>());
    }

    /**
     * change password
     * @param token
     * @param changePassReqDTO
     * @return
     */
    @PostMapping("/change-password")
    public ResponseEntity<GeneralResponse<Object>> changePassword(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String token,
            @RequestBody @Valid ChangePassReqDTO changePassReqDTO
    ) {
        try {
            userService.changePassword(token, changePassReqDTO);
        } catch (UserException.CredentialError credentialError) {
            throw new BaseResponseException(ResponseStatusCodeEnum.CREDENTIAL_ERROR);
        } catch (UserException.NotFound notFound) {
            throw new BaseResponseException(ResponseStatusCodeEnum.USER_NOT_FOUND);
        }  catch (AuthenticationException.NotTokenAtFirstParam e) {
            throw new BaseResponseException(ResponseStatusCodeEnum.NOT_TOKEN_AT_FIRST_PARAM);
        } catch (AuthenticationException.UserDoesNotHaveAccess e) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        } catch (Exception e) {
            log.error(e.getMessage());
            throw new BaseResponseException(ResponseStatusCodeEnum.BUSINESS_ERROR);
        }
        return responseFactory.success(new GeneralResponse<>());
    }
}
