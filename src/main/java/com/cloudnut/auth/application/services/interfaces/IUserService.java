package com.cloudnut.auth.application.services.interfaces;

import com.cloudnut.auth.application.dto.request.auth.ChangePassReqDTO;
import com.cloudnut.auth.application.dto.request.user.UserSignInReqDTO;
import com.cloudnut.auth.application.dto.request.user.UserUpdateReqDTO;
import com.cloudnut.auth.application.dto.response.common.PagingResponseDTO;
import com.cloudnut.auth.application.dto.response.user.UserDetailResDTO;
import com.cloudnut.auth.application.dto.response.user.UserResDTO;
import com.cloudnut.auth.application.dto.response.user.UserTokenResDTO;
import com.cloudnut.auth.application.exception.AuthenticationException;
import com.cloudnut.auth.application.exception.UserException;
import org.springframework.data.domain.Pageable;

import javax.mail.MessagingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public interface IUserService {
    UserDetailResDTO findCurrentUser(String token) throws AuthenticationException.MissingToken, UserException.UserLocked;
    UserTokenResDTO signIn(UserSignInReqDTO signInReqDTO) throws UserException.CredentialError, UserException.UserLocked, UserException.UserNotVerify;
    void verifyEmail(String verifyCode) throws UserException.NotFound;
    UserDetailResDTO updateUser(String token,Long userId, UserUpdateReqDTO userUpdateReqDTO) throws UserException.NotFound, NoSuchAlgorithmException, IOException, InvalidKeySpecException;
    PagingResponseDTO<UserResDTO> searchService(String token, String searchText, Pageable pageable);
    void forgotPassword(String email) throws UserException.NotFound, UnsupportedEncodingException, MessagingException;
    void changePassword(String token, ChangePassReqDTO changePassReqDTO) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, UserException.NotFound, UserException.CredentialError;
}
