package com.cloudnut.auth.application.services.impl;

import com.cloudnut.auth.application.aop.annotation.AuthenticationAOP;
import com.cloudnut.auth.application.dto.request.auth.ChangePassReqDTO;
import com.cloudnut.auth.application.dto.request.user.UserSignInReqDTO;
import com.cloudnut.auth.application.dto.request.user.UserUpdateReqDTO;
import com.cloudnut.auth.application.dto.response.common.PagingResponseDTO;
import com.cloudnut.auth.application.dto.response.user.UserDetailResDTO;
import com.cloudnut.auth.application.dto.response.user.UserResDTO;
import com.cloudnut.auth.application.dto.response.user.UserTokenResDTO;
import com.cloudnut.auth.application.exception.AuthenticationException;
import com.cloudnut.auth.application.exception.UserException;
import com.cloudnut.auth.application.services.interfaces.IAuthService;
import com.cloudnut.auth.application.services.interfaces.IUserService;
import com.cloudnut.auth.client.notification.NoticeClient;
import com.cloudnut.auth.infrastructure.entity.UserEntityDB;
import com.cloudnut.auth.infrastructure.entity.UserRoleEntityDB;
import com.cloudnut.auth.infrastructure.repository.UserEntityRepo;
import com.cloudnut.auth.infrastructure.repository.UserRoleEntityRepo;
import com.cloudnut.auth.utils.ProviderUtils;
import com.cloudnut.auth.utils.RoleConstants;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.transaction.Transactional;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

@Service
@Slf4j
public class UserService implements IUserService {

    @Value("${mail.send_email}")
    private String MAIL_SENDER;

    @Value("${mail.send_name}")
    private String MAIL_SENDER_NAME;

    @Value("${mail.send_change_pass_subject}")
    private String MAIL_SENDER_CHANGE_PASS_SUBJECT;

    @Value("${mail.send_change_pass_content}")
    private String MAIL_SENDER_CHANGE_PASS_CONTENT;

    @Autowired
    private UserEntityRepo userEntityRepo;

    @Autowired
    private UserRoleEntityRepo userRoleEntityRepo;

    @Autowired
    private BCryptPasswordEncoder pwdEnc;

    @Autowired
    private IAuthService authService;

    @Autowired
    private JavaMailSender javaMailSender;

    @Autowired
    private NoticeClient noticeClient;

    /**
     * get current user detail
     * @param token
     * @return
     * @throws AuthenticationException.MissingToken
     * @throws UserException.UserLocked
     */
    @Override
    @AuthenticationAOP()
    public UserDetailResDTO findCurrentUser(String token) throws AuthenticationException.MissingToken, UserException.UserLocked {
        UserDetailResDTO userDetailResDTO;
        try {
            Long userId = authService.getUserId(token);
            UserEntityDB userEntityDB = userEntityRepo.findById(userId).get();
            if (!userEntityDB.getIsActive()) {
                throw new UserException.UserLocked();
            }
            UserRoleEntityDB role = userRoleEntityRepo.findByUserId(userId);
            userDetailResDTO = UserDetailResDTO.builder()
                    .id(userId)
                    .email(userEntityDB.getEmail())
                    .name(userEntityDB.getName())
                    .imageUrl(userEntityDB.getImageUrl())
                    .role(role.getRole())
                    .build();
        } catch (UserException.UserLocked e) {
            throw e;
        } catch (Exception e) {
            throw new AuthenticationException.MissingToken();
        }
        return userDetailResDTO;
    }

    /**
     * sign in
     * @param signInReqDTO
     * @return
     * @throws UserException.CredentialError
     */
    @Override
    public UserTokenResDTO signIn(UserSignInReqDTO signInReqDTO) throws UserException.CredentialError,
            UserException.UserLocked, UserException.UserNotVerify {
        // find user
        Optional<UserEntityDB> userEntityDBOption = userEntityRepo
                .findByEmailAndProvider(signInReqDTO.getEmail(), ProviderUtils.PROVIDER.LOCAL);
        if (!userEntityDBOption.isPresent()) {
            throw new UserException.CredentialError();
        }

        UserEntityDB userEntityDB = userEntityDBOption.get();
        if (!pwdEnc.matches(signInReqDTO.getPassword(), userEntityDB.getPassword())) {
            throw new UserException.CredentialError();
        }

        if (!userEntityDB.getIsActive()) {
            throw new UserException.UserLocked();
        }

        if (!userEntityDB.getEmailVerified()) {
            throw new UserException.UserNotVerify();
        }

        String token;
        try {
            token = authService.generateToken(userEntityDB.getId());
        } catch (Exception e) {
            throw new RuntimeException();
        }
        return UserTokenResDTO.builder()
                .accessToken(token)
                .build();
    }

    /**
     * verify user
     * @param verifyCode
     * @throws UserException.NotFound
     */
    @Override
    public void verifyEmail(String verifyCode) throws UserException.NotFound {
        Optional<UserEntityDB> entityDBOptional = userEntityRepo.findByVerifyCode(verifyCode);
        if (!entityDBOptional.isPresent()) {
            throw new UserException.NotFound();
        }
        UserEntityDB userEntityDB = entityDBOptional.get();
        userEntityDB.setEmailVerified(true);
        userEntityRepo.save(userEntityDB);
    }

    /**
     * update user
     * @param token
     * @param userId
     * @param userUpdateReqDTO
     * @return
     * @throws UserException.NotFound
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeySpecException
     */
    @Override
    @AuthenticationAOP(roles = RoleConstants.ADMIN)
    public UserDetailResDTO updateUser(String token, Long userId, UserUpdateReqDTO userUpdateReqDTO) throws
            UserException.NotFound, NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        String username = authService.getUserName(token);
        Long userTokenId = authService.getUserId(token);
        Optional<UserEntityDB> entityDBOptional = userEntityRepo.findById(userId);
        if (!entityDBOptional.isPresent()) {
            throw new UserException.NotFound();
        }
        UserEntityDB userEntityDB = entityDBOptional.get();

        if (userTokenId.equals(userEntityDB.getId()) || userEntityDB.getIsDefault()) {
            throw new AuthenticationException.UserDoesNotHaveAccess();
        }

        if (userUpdateReqDTO.getLock() != null && userUpdateReqDTO.getLock()) {
            userEntityDB.setIsActive(false);
        } else {
            userEntityDB.setIsActive(true);
        }
        userEntityRepo.save(userEntityDB);

        UserRoleEntityDB userRoleEntityDB = userRoleEntityRepo.findByUserId(userId);
        userRoleEntityDB.setRole(userUpdateReqDTO.getUserRole());
        userRoleEntityDB.setUserId(userEntityDB.getId());
        userRoleEntityDB.setUpdatedDate(new Date());
        userRoleEntityDB.setUpdatedBy(username);
        userRoleEntityRepo.save(userRoleEntityDB);

        noticeClient.notice(token, userId, userEntityDB.getName(),
                userUpdateReqDTO.getUserRole() + "", username);

        return UserDetailResDTO.builder()
                .id(userEntityDB.getId())
                .email(userEntityDB.getEmail())
                .name(userEntityDB.getName())
                .imageUrl(userEntityDB.getImageUrl())
                .role(userRoleEntityDB.getRole())
                .build();
    }

    /**
     * search user service
     * @param token
     * @param searchText
     * @param pageable
     * @return
     */
    @Override
    @AuthenticationAOP(roles = RoleConstants.ADMIN)
    public PagingResponseDTO<UserResDTO> searchService(String token, String searchText, Pageable pageable) {
        Page<UserEntityDB> userEntityDBPage = userEntityRepo
                .findByEmailContainingIgnoreCaseOrNameContainingIgnoreCase(searchText, searchText, pageable);
        List<UserEntityDB> userEntityDBS = userEntityDBPage.getContent();
        List<UserResDTO> userResDTOS = new ArrayList<>();
        for (int i = 0; i < userEntityDBS.size(); i++) {
            UserEntityDB userEntityDB = userEntityDBS.get(i);
            UserRoleEntityDB userRoleEntityDB = userRoleEntityRepo.findByUserId(userEntityDB.getId());
            UserResDTO userResDTO = UserResDTO.builder()
                    .id(userEntityDB.getId())
                    .email(userEntityDB.getEmail())
                    .name(userEntityDB.getName())
                    .isActive(userEntityDB.getIsActive())
                    .provider(userEntityDB.getProvider())
                    .role(userRoleEntityDB.getRole())
                    .build();
            userResDTOS.add(userResDTO);
        }
        return PagingResponseDTO.from(userResDTOS, userEntityDBPage.getTotalPages(), userEntityDBPage.getTotalElements());
    }

    /**
     * forgot password
     * @param email
     */
    @Override
    @Transactional
    public void forgotPassword(String email) throws UserException.NotFound,
            UnsupportedEncodingException, MessagingException {
        // check user existed or not
        Optional<UserEntityDB> entityDBOptional =
                userEntityRepo.findByEmailContainingIgnoreCaseAndProvider(email, ProviderUtils.PROVIDER.LOCAL);
        if (!entityDBOptional.isPresent()) {
            throw new UserException.NotFound();
        }

        UserEntityDB userEntityDB = entityDBOptional.get();

        String newPass = UUID.randomUUID().toString().replaceAll("-", "");
        // send email
        String encPass = pwdEnc.encode(newPass);
        sendNewPassEmail(userEntityDB, newPass);
        userEntityDB.setPassword(encPass);
        userEntityRepo.save(userEntityDB);
    }

    /**
     * change password
     * @param token
     * @param changePassReqDTO
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeySpecException
     * @throws UserException.NotFound
     * @throws UserException.CredentialError
     */
    @Override
    @AuthenticationAOP()
    public void changePassword(String token, ChangePassReqDTO changePassReqDTO)
            throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, UserException.NotFound,
            UserException.CredentialError {
        Long userId = authService.getUserId(token);

        Optional<UserEntityDB> entityDBOptional = userEntityRepo.findById(userId);
        if (!entityDBOptional.isPresent() ||
                (entityDBOptional.get().getProvider() != ProviderUtils.PROVIDER.LOCAL)) {
            throw new UserException.NotFound();
        }
        UserEntityDB userEntityDB = entityDBOptional.get();
        if (!pwdEnc.matches(changePassReqDTO.getOldPass(), userEntityDB.getPassword())) {
            throw new UserException.CredentialError();
        }
        userEntityDB.setPassword(pwdEnc.encode(changePassReqDTO.getNewPass()));
        userEntityRepo.save(userEntityDB);
    }


    /**
     * send change pass email
     * @param userEntityDB
     * @param newPass
     * @throws MessagingException
     * @throws UnsupportedEncodingException
     */
    private void sendNewPassEmail(UserEntityDB userEntityDB, String newPass) throws
            MessagingException, UnsupportedEncodingException {
        MimeMessage message = javaMailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);

        helper.setFrom(MAIL_SENDER, MAIL_SENDER_NAME);
        helper.setTo(userEntityDB.getEmail());
        helper.setSubject(MAIL_SENDER_CHANGE_PASS_SUBJECT);

        String content = MAIL_SENDER_CHANGE_PASS_CONTENT.replace("[[name]]", userEntityDB.getName());
        content = content.replace("[[PASSWORD]]", newPass);
        helper.setText(content, true);
        javaMailSender.send(message);
    }
}
