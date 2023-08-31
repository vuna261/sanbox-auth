package com.cloudnut.auth.client.notification;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class NoticeReq {
    @JsonProperty("noticeUserId")
    @SerializedName("noticeUserId")
    private Long noticeUserId;

    @JsonProperty("noticeUser")
    @SerializedName("noticeUser")
    private String noticeUser;

    @JsonProperty("noticeType")
    @SerializedName("noticeType")
    private NoticeUtils.NOTIFICATION_TYPE noticeType;

    @JsonProperty("notificationType")
    @SerializedName("notificationType")
    private String notificationType;

    @JsonProperty("noticeContent")
    @SerializedName("noticeContent")
    private String noticeContent;

    @JsonProperty("labId")
    @SerializedName("labId")
    private Long labId;
}
