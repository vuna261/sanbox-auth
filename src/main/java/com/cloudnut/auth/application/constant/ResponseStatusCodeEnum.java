package com.cloudnut.auth.application.constant;

import com.cloudnut.auth.application.dto.response.common.ResponseStatusCode;

public class ResponseStatusCodeEnum {
    private ResponseStatusCodeEnum() {}
    public static final ResponseStatusCode SUCCESS = ResponseStatusCode.builder().code("00").httpCode(200).build();
    public static final ResponseStatusCode BUSINESS_ERROR = ResponseStatusCode.builder().code("BSA0001").httpCode(500).build();
    public static final ResponseStatusCode VALIDATION_ERROR = ResponseStatusCode.builder().code("BSA0002").httpCode(400).build();
    public static final ResponseStatusCode INTERNAL_GENERAL_SERVER_ERROR = ResponseStatusCode.builder().code("BSA0003").httpCode(500).build();
    public static final ResponseStatusCode ERROR_BODY_CLIENT = ResponseStatusCode.builder().code("BSA0004").httpCode(400).build();
    public static final ResponseStatusCode ERROR_BODY_REQUIRED = ResponseStatusCode.builder().code("BSA0005").httpCode(400).build();
    public static final ResponseStatusCode AUTHORIZED_ERROR = ResponseStatusCode.builder().code("AU0001").httpCode(403).build();
    public static final ResponseStatusCode NOT_TOKEN_AT_FIRST_PARAM = ResponseStatusCode.builder().code("AU0002").httpCode(401).build();

    public static final ResponseStatusCode USER_ALREADY_EXISTED = ResponseStatusCode.builder().code("US40901").httpCode(200).build();
    public static final ResponseStatusCode GEN_TOKEN_EXCEPTION = ResponseStatusCode.builder().code("TK50001").httpCode(200).build();
    public static final ResponseStatusCode CREDENTIAL_ERROR = ResponseStatusCode.builder().code("US40001").httpCode(200).build();
    public static final ResponseStatusCode USER_LOCKED = ResponseStatusCode.builder().code("US40101").httpCode(200).build();
    public static final ResponseStatusCode USER_NOT_VERIFY = ResponseStatusCode.builder().code("US40102").httpCode(200).build();
    public static final ResponseStatusCode USER_NOT_FOUND = ResponseStatusCode.builder().code("US40401").httpCode(200).build();
}
