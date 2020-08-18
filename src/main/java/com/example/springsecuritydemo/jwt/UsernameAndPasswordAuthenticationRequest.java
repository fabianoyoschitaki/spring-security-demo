package com.example.springsecuritydemo.jwt;

import lombok.Data;
import lombok.ToString;

@Data
public class UsernameAndPasswordAuthenticationRequest {
    private String username;
    private String password;
}
