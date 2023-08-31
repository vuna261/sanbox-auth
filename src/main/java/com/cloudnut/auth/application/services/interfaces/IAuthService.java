package com.cloudnut.auth.application.services.interfaces;

import com.cloudnut.auth.application.dto.request.user.UserSignUpReqDTO;
import com.cloudnut.auth.application.exception.UserException;
import com.cloudnut.auth.domain.User.UserPrincipal;

import javax.mail.MessagingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public interface IAuthService {
    boolean checkAuthorization(String token, String[] roles);
    String getUserName(String token) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException;
    String generateToken(Long userId) throws UserException.NotFound, NoSuchAlgorithmException, IOException, InvalidKeySpecException;
    String generateToken(UserPrincipal principal);
    Long getUserId(String token) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException;
    void signUp(UserSignUpReqDTO signUpReqDTO) throws UserException.AlreadyExisted, UnsupportedEncodingException, MessagingException;
}
