package com.cloudnut.auth.client.notification;

import com.cloudnut.auth.client.utils.IRetrofitService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import retrofit2.Retrofit;

@Component
@Slf4j
public class NoticeClientImpl implements NoticeClient{
    @Value("${vil.orchestration.host}")
    private String ORCHESTRATION_HOST;

    @Autowired
    IRetrofitService retrofitService;

    /**
     * send notification
     * @param token
     * @param noticeUserId
     * @param noticeUserName
     * @param userRole
     * @param noticeBy
     */
    @Override
    public void notice(String token, Long noticeUserId, String noticeUserName, String userRole, String noticeBy) {
        try {
            Retrofit retrofit = retrofitService.getRetrofit(ORCHESTRATION_HOST);
            NoticeApi noticeApi = retrofit.create(NoticeApi.class);
            NoticeReq noticeReq = NoticeReq.builder()
                    .noticeUserId(noticeUserId)
                    .noticeUser(noticeUserName)
                    .noticeType(NoticeUtils.NOTIFICATION_TYPE.DIRECT)
                    .noticeContent(NoticeUtils.userChangeMessage(userRole, noticeBy))
                    .notificationType("NONE")
                    .labId(0L)
                    .build();
            noticeApi.createNotice(noticeReq, token).execute();
        } catch (Exception e) {
            log.warn("SEND NOTICE FAILURE: {}", e);
        }
    }
}
