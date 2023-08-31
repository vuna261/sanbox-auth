package com.cloudnut.auth.application.exception;

public class UserException extends Exception {
    private UserException() {}

    public static class AlreadyExisted extends Exception {}

    public static class NotFound extends Exception {}

    public static class UserLocked extends Exception {}

    public static class UserNotVerify extends Exception {}

    public static class CredentialError extends Exception {}
}
