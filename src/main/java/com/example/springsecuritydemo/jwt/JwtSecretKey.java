package com.example.springsecuritydemo.jwt;

import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;

@Configuration
@Slf4j
public class JwtSecretKey {
    
    private final JwtConfig jwtConfig;
    
    @Autowired
    public JwtSecretKey(JwtConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
    }
    
    @Bean
    public SecretKey secretKey() {
        log.info("secretKey: {}", jwtConfig.getSecretKey());
        return Keys.hmacShaKeyFor(jwtConfig.getSecretKey().getBytes());
    }
}
