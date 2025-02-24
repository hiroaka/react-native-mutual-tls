package com.reactlibrary;

import android.annotation.SuppressLint;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.modules.network.OkHttpClientFactory;
import com.facebook.react.modules.network.ReactCookieJarContainer;

import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class CustomClientFactory implements OkHttpClientFactory {
    public static String certificateFileP12;
    public static String certificatePassword;

    @Override
    public OkHttpClient createNewNetworkModuleClient() {
        String TAG = "OkHttpClientFactory";

        try {
            byte[] decbytes = Base64.decode(certificateFileP12, Base64.DEFAULT);
            InputStream stream = new ByteArrayInputStream(decbytes);

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(stream, certificatePassword.toCharArray());

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("X509");
            keyManagerFactory.init(keyStore, certificatePassword.toCharArray());

            X509TrustManager trustManager = new X509TrustManager() {
                @SuppressLint("TrustAllX509TrustManager")
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                @SuppressLint("TrustAllX509TrustManager")
                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            };
            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(keyManagerFactory.getKeyManagers(), new TrustManager[]{ trustManager }, new SecureRandom());
            OkHttpClient.Builder builder = new OkHttpClient.Builder()
                    .sslSocketFactory(sslContext.getSocketFactory(), trustManager)
                    .hostnameVerifier(new HostnameVerifier() {
                        @Override
                        public boolean verify(String hostname, SSLSession session) {
                            return true;
                        }
                    })
                    .cookieJar(new ReactCookieJarContainer());

            builder.addInterceptor(new CustomInterceptor());

            return builder.build();

        } catch (
                Exception e) {
            Log.e(TAG, e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private static class CustomInterceptor implements Interceptor {
        @Override
        public Response intercept(Chain chain) throws IOException {
            Request originalRequest = chain.request();

            // Log request headers
            Map<String, String> uppercaseHeaders = convertHeadersToUppercase(originalRequest.headers());

            okhttp3.Headers.Builder headersBuilder = new okhttp3.Headers.Builder();
            for (Map.Entry<String, String> entry : uppercaseHeaders.entrySet()) {
                headersBuilder.add(entry.getKey(), entry.getValue());
            }

            Request newRequest = originalRequest.newBuilder()
                    .headers(headersBuilder.build())
                    .build();

            Response response = chain.proceed(newRequest);

            return response;
        }

        private Map<String, String> convertHeadersToUppercase(okhttp3.Headers headers) {
            Map<String, String> uppercaseHeaders = new HashMap<>();
            for (int i = 0, size = headers.size(); i < size; i++) {
                String key = headers.name(i).toUpperCase();
                String value = headers.value(i);
                uppercaseHeaders.put(key, value);
            }
            return uppercaseHeaders;
        }
    }
}
