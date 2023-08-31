package com.cloudnut.auth.client.notification;

public class NoticeUtils {
    private NoticeUtils() {}
    public enum NOTIFICATION_TYPE {
        ALL,
        ADMIN,
        TRAINER,
        TRAINEE,
        DIRECT
    }

    public static String USER_ROLE_UPDATE = "Tài khoản của bạn đã được cập nhật thành <b>[[role]]</b> bởi người dùng <b><i>[[user]]</i></b>.";

    public static String userChangeMessage(String role, String userName) {
        String message = USER_ROLE_UPDATE.replace("[[role]]", role)
                .replace("[[user]]", userName);
        return message;
    }
}
