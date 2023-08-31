package com.cloudnut.auth.client.notification;

public interface NoticeClient {
    void notice(String token, Long noticeUserId, String noticeUserName, String userRole, String noticeBy);
}
