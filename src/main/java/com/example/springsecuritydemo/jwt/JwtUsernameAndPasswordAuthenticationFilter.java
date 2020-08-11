package com.example.springsecuritydemo.jwt;

import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * Verify credentials
 * 
 * @author fabiano
 *
 */
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    
    @Autowired
    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        try {
            System.out.println("attemptAuthentication");
            // retrieved username and password from request, but could be any place
            UsernameAndPasswordAuthenticationRequest authenticationRequest = new ObjectMapper()
                    .readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);
            
            // principal and credentials
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),
                    authenticationRequest.getPassword());
            
            // will make sure username exists and check if password is correct
            Authentication authenticated = authenticationManager.authenticate(authentication);
            return authenticated;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // invoked after attemptAuthentication is successful
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication");
        // generate token
        String token = Jwts.builder()
            .setSubject(authResult.getName()) // linda, tom, annasmith
            .claim("authorities", authResult.getAuthorities())
            .setIssuedAt(new Date())
            .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusWeeks(2)))
            .signWith(Keys.hmacShaKeyFor("secure-key-very-long-12345678901234567890".getBytes()))
            .compact();
        // send back to client
        System.out.println("Send authorization header Bearer " + token);
        response.addHeader("Authorization", "Bearer " + token);
    }
}
