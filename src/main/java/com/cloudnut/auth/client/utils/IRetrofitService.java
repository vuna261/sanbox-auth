package com.cloudnut.auth.client.utils;

import retrofit2.Retrofit;

public interface IRetrofitService {
    Retrofit getRetrofit(String url);
}
