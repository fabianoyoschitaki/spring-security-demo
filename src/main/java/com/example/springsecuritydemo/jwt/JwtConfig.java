package com.example.springsecuritydemo.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import com.google.common.net.HttpHeaders;


@ConfigurationProperties(prefix = "application.jwt")
@Component
public class JwtConfig {
    
    // application.properties will get injected here
    private String secretKey;
    private String tokenPrefix;
    private Integer tokenExpirationAfterDay;
    
    public JwtConfig() {
    }

    public String getSecretKey() {
        return secretKey;
    }
    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }
    public String getTokenPrefix() {
        return tokenPrefix;
    }
    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
    }
    public Integer getTokenExpirationAfterDay() {
        return tokenExpirationAfterDay;
    }
    public void setTokenExpirationAfterDay(Integer tokenExpirationAfterDay) {
        this.tokenExpirationAfterDay = tokenExpirationAfterDay;
    }
    
    public String getAuthorizationHeader() {
        return HttpHeaders.AUTHORIZATION;
    }
}
