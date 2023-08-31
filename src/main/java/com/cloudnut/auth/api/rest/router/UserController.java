package com.cloudnut.auth.api.rest.router;

import com.cloudnut.auth.api.rest.factory.response.ResponseFactory;
import com.cloudnut.auth.application.constant.ResponseStatusCodeEnum;
import com.cloudnut.auth.application.dto.request.user.UserUpdateReqDTO;
import com.cloudnut.auth.application.dto.response.common.GeneralResponse;
import com.cloudnut.auth.application.dto.response.common.PagingResponseDTO;
import com.cloudnut.auth.application.dto.response.user.UserDetailResDTO;
import com.cloudnut.auth.application.dto.response.user.UserResDTO;
import com.cloudnut.auth.application.exception.AuthenticationException;
import com.cloudnut.auth.application.exception.BaseResponseException;
import com.cloudnut.auth.application.exception.UserException;
import com.cloudnut.auth.application.services.interfaces.IUserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import javax.validation.Valid;

@RestController
@RequestMapping("${app.base-url}/users")
@Slf4j
public class UserController {

    @Autowired
    IUserService userService;

    @Autowired
    ResponseFactory responseFactory;

    /**
     * get logged user context
     * @param token
     * @return
     */
    @GetMapping("/me")
    public ResponseEntity<GeneralResponse<UserDetailResDTO>> getCurrentUser(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String token
    ) {
        UserDetailResDTO userDetailResDTO;
        try {
            userDetailResDTO = userService.findCurrentUser(token);
        } catch (UserException.UserLocked userLocked) {
            throw new BaseResponseException(ResponseStatusCodeEnum.USER_LOCKED);
        } catch (AuthenticationException.MissingToken missingToken) {
            throw new BaseResponseException(ResponseStatusCodeEnum.NOT_TOKEN_AT_FIRST_PARAM);
        } catch (Exception e) {
            log.error(e.getMessage());
            throw new BaseResponseException(ResponseStatusCodeEnum.BUSINESS_ERROR);
        }
        return responseFactory.success(userDetailResDTO);
    }

    /**
     * update user (lock user, promote role)
     * @param token
     * @param id
     * @param userUpdateReqDTO
     * @return
     */
    @PutMapping("/{id}")
    public ResponseEntity<GeneralResponse<UserDetailResDTO>> updateUser(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String token,
            @PathVariable("id") Long id,
            @RequestBody @Valid UserUpdateReqDTO userUpdateReqDTO
    ) {
        UserDetailResDTO userDetailResDTO;
        try {
            userDetailResDTO = userService.updateUser(token, id, userUpdateReqDTO);
        } catch (UserException.NotFound notFound) {
            throw new BaseResponseException(ResponseStatusCodeEnum.USER_NOT_FOUND);
        } catch (AuthenticationException.NotTokenAtFirstParam e) {
            throw new BaseResponseException(ResponseStatusCodeEnum.NOT_TOKEN_AT_FIRST_PARAM);
        } catch (AuthenticationException.UserDoesNotHaveAccess e) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new BaseResponseException(ResponseStatusCodeEnum.BUSINESS_ERROR);
        }
        return responseFactory.success(userDetailResDTO);
    }

    /**
     * search user
     * @param token
     * @param searchText
     * @param pageNum
     * @param pageSize
     * @return
     */
    @GetMapping()
    public ResponseEntity<GeneralResponse<PagingResponseDTO<UserResDTO>>> searchUser(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String token,
            @RequestParam(value = "searchText", required = false, defaultValue = "") String searchText,
            @RequestParam(value = "page", required = false, defaultValue = "0") Integer pageNum,
            @RequestParam(value = "size", required = false, defaultValue = "5") Integer pageSize
    ) {
        PagingResponseDTO<UserResDTO> responseDTO;
        try {
            Pageable pageable = PageRequest.of(pageNum, pageSize, Sort.by("email").ascending());
            responseDTO = userService.searchService(token, searchText, pageable);
        }  catch (AuthenticationException.NotTokenAtFirstParam e) {
            throw new BaseResponseException(ResponseStatusCodeEnum.NOT_TOKEN_AT_FIRST_PARAM);
        } catch (AuthenticationException.UserDoesNotHaveAccess e) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new BaseResponseException(ResponseStatusCodeEnum.BUSINESS_ERROR);
        }
        return responseFactory.success(responseDTO);
    }
}
