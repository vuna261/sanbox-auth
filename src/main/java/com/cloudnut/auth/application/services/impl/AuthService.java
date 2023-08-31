package com.cloudnut.auth.application.services.impl;

import com.cloudnut.auth.application.dto.request.user.UserSignUpReqDTO;
import com.cloudnut.auth.application.exception.AuthenticationException;
import com.cloudnut.auth.application.exception.UserException;
import com.cloudnut.auth.application.services.interfaces.IAuthService;
import com.cloudnut.auth.domain.User.UserPrincipal;
import com.cloudnut.auth.infrastructure.entity.UserEntityDB;
import com.cloudnut.auth.infrastructure.entity.UserRoleEntityDB;
import com.cloudnut.auth.infrastructure.repository.UserEntityRepo;
import com.cloudnut.auth.infrastructure.repository.UserRoleEntityRepo;
import com.cloudnut.auth.utils.*;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.utility.RandomString;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

@Service
@Slf4j
public class AuthService implements IAuthService {

    @Value("${jwt.private-key}")
    private String PRIVATE_KEY;

    @Value("${jwt.public-key}")
    private String PUBLIC_KEY;

    @Value("${jwt.token_lifetime}")
    private Long TOKEN_LIFE_TIME;

    @Value("${mail.site_url}")
    private String MAIL_URL;

    @Value("${mail.send_email}")
    private String MAIL_SENDER;

    @Value("${mail.send_name}")
    private String MAIL_SENDER_NAME;

    @Value("${mail.send_subject}")
    private String MAIL_SENDER_SUBJECT;

    @Value("${mail.send_content}")
    private String MAIL_SENDER_CONTENT;

    @Autowired
    private UserRoleEntityRepo userRoleEntityRepo;

    @Autowired
    private UserEntityRepo userEntityRepo;

    @Autowired
    private BCryptPasswordEncoder pwdEnc;

    @Autowired
    private JavaMailSender javaMailSender;

    /**
     * validate token and role
     * @param token
     * @param roles
     * @return
     */
    @Override
    public boolean checkAuthorization(String token, String[] roles) {
        try {
            List<String> claimRole = getRoles(token);
            if ((roles.length == 0 && claimRole.size() > 0) || claimRole.contains(UserUtils.ROLE_ADMIN)) {
                return true;
            }

            boolean roleCheck = false;
            if (roles.length > 0) {
                for (int i = 0; i < roles.length; i++) {
                    if (claimRole.contains(roles[i].toUpperCase())) {
                        roleCheck = true;
                        break;
                    }
                }
            }
            return roleCheck;

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * get username from token
     * @param token
     * @return
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeySpecException
     */
    @Override
    public String getUserName(String token) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        Claims claims = JwtUtils.getAllClaimsFromToken(token, FileUtils.getPublicKeyFromFile(PUBLIC_KEY));
        return (String) claims.get(Constants.USERNAME);
    }

    /**
     * generate token by user id
     * @param userId
     * @return
     * @throws UserException.NotFound
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeySpecException
     */
    @Override
    public String generateToken(Long userId) throws UserException.NotFound, NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        Optional<UserEntityDB> entityDBOptional = userEntityRepo.findById(userId);
        if (!entityDBOptional.isPresent()) {
            throw new UserException.NotFound();
        }

        UserEntityDB userEntityDB = entityDBOptional.get();

        Map<String, Object> claimsList = buildClaim(userEntityDB);

        return JwtUtils.generateJwt(FileUtils.getPrivateKeyFromFile(PRIVATE_KEY), claimsList, userEntityDB.getId().toString(), TOKEN_LIFE_TIME);
    }

    /**
     * generate token from user principal
     * @param principal
     * @return
     */
    @Override
    public String generateToken(UserPrincipal principal) {
        Long id = principal.getId();
        UserEntityDB userEntityDB = userEntityRepo.findById(id).get();
        Map<String, Object> claimsList = buildClaim(userEntityDB);
        claimsList.put(Constants.ATTRIBUTES, principal.getAttributes());

        String token;
        try {
            token = JwtUtils.generateJwt(FileUtils.getPrivateKeyFromFile(PRIVATE_KEY), claimsList, userEntityDB.getId().toString(), TOKEN_LIFE_TIME);
        } catch (Exception e) {
            token = null;
        }

        return token;
    }

    /**
     * get user id from token
     * @param token
     * @return
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeySpecException
     */
    @Override
    public Long getUserId(String token) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        Claims claims = JwtUtils.getAllClaimsFromToken(token, FileUtils.getPublicKeyFromFile(PUBLIC_KEY));
        return Long.parseLong(claims.getSubject());
    }

    /**
     * build claims from entity
     * @param userEntityDB
     * @return
     */
    private Map<String, Object> buildClaim(UserEntityDB userEntityDB) {
        UserRoleEntityDB userRoleEntityDB = userRoleEntityRepo.findByUserId(userEntityDB.getId());

        Map<String, Object> claimsList = new HashMap<>();
        List<GrantedAuthority> authorities = UserUtils.buildAuthorityByRole(userRoleEntityDB.getRole());
        claimsList.put(Constants.ROLE_UPDATE, userRoleEntityDB.getUpdatedDate());
        claimsList.put(Constants.AUTHORITY, authorities);
        claimsList.put(Constants.EMAIL, userEntityDB.getEmail());
        claimsList.put(Constants.USERNAME, userEntityDB.getName());
        return claimsList;
    }

    /**
     * sign up new user
     * @param signUpReqDTO
     * @throws UserException.AlreadyExisted
     * @throws UnsupportedEncodingException
     * @throws MessagingException
     */
    @Override
    public void signUp(UserSignUpReqDTO signUpReqDTO) throws UserException.AlreadyExisted,
            UnsupportedEncodingException, MessagingException {
        // check email already existed or not for provider local
        Optional<UserEntityDB> entityDBOptional =
                userEntityRepo.findByEmailContainingIgnoreCaseAndProvider(signUpReqDTO.getEmail(), ProviderUtils.PROVIDER.LOCAL);
        if (entityDBOptional.isPresent()) {
            throw new UserException.AlreadyExisted();
        }

        String verifyCode = RandomString.make(64);

        UserEntityDB userEntityDB = UserEntityDB.builder()
                .email(signUpReqDTO.getEmail())
                .emailVerified(false)
                .isActive(true)
                .isDefault(false)
                .password(pwdEnc.encode(signUpReqDTO.getPassword()))
                .name(signUpReqDTO.getName())
                .provider(ProviderUtils.PROVIDER.LOCAL)
                .verifyCode(verifyCode)
                .build();

        userEntityDB = userEntityRepo.save(userEntityDB);

        // store role
        UserRoleEntityDB userRoleEntityDB = UserRoleEntityDB.builder()
                .userId(userEntityDB.getId())
                .role(UserUtils.ROLE.TRAINEE)
                .createdBy(Constants.SYSTEM)
                .updatedBy(Constants.SYSTEM)
                .createdDate(new Date())
                .updatedDate(new Date())
                .build();

        userRoleEntityRepo.save(userRoleEntityDB);

        sendVerificationEmail(userEntityDB);
    }

    /**
     * send verify email
     * @param userEntityDB
     * @throws UnsupportedEncodingException
     * @throws MessagingException
     */
    private void sendVerificationEmail(UserEntityDB userEntityDB) throws
            UnsupportedEncodingException, MessagingException {
        MimeMessage message = javaMailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);

        helper.setFrom(MAIL_SENDER, MAIL_SENDER_NAME);
        helper.setTo(userEntityDB.getEmail());
        helper.setSubject(MAIL_SENDER_SUBJECT);

        String content = MAIL_SENDER_CONTENT.replace("[[name]]", userEntityDB.getName());
        String verifyUrl = MAIL_URL + userEntityDB.getVerifyCode();
        content = content.replace("[[URL]]", verifyUrl);
        helper.setText(content, true);
        javaMailSender.send(message);
    }

    /**
     * get list role from token
     * @param token
     * @return
     * @throws AuthenticationException.MissingToken
     */
    private List<String> getRoles(String token) throws AuthenticationException.MissingToken {
        Claims claims = getClaimsFromToken(token);
        List<LinkedHashMap<String, String>> roles = (List<LinkedHashMap<String, String>>) claims.get(Constants.AUTHORITY);
        List<String> claimRoles = new ArrayList<>();
        for (LinkedHashMap<String, String> role: roles) {
            String roleTmp = role.get("authority");
            roleTmp = roleTmp.replaceAll(Constants.ROLE_PREFIX, "").toUpperCase();
            claimRoles.add(roleTmp);
        }
        return claimRoles;
    }

    /**
     * get claims from token and validate this token
     * @param token
     * @return
     * @throws AuthenticationException.MissingToken
     */
    private Claims getClaimsFromToken(String token) throws AuthenticationException.MissingToken {
        Claims claims;
        try {
            // validate token
            if (JwtUtils.validateToken(token, FileUtils.getPublicKeyFromFile(PUBLIC_KEY))) {
                throw new AuthenticationException.MissingToken();
            }
            // get all claims from token
            claims = (Claims) JwtUtils.getAllClaimsFromToken(token, FileUtils.getPublicKeyFromFile(PUBLIC_KEY));
        } catch (Exception e) {
            throw new AuthenticationException.MissingToken();
        }
        return claims;
    }
}