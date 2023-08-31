package com.cloudnut.auth.client.notification;

import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.Header;
import retrofit2.http.Headers;
import retrofit2.http.POST;

public interface NoticeApi {
    @Headers({ "Content-Type: application/json;charset=UTF-8"})
    @POST("/vil-mgmt/api/v1/notifications")
    Call<Object> createNotice(@Body NoticeReq noticeReq, @Header("Authorization") String token);
}
