package com.example.springsecuritydemo.jwt;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.google.common.base.Strings;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

// onceperrequestfilter = executed once per request. 
// sometimes filters can be invoked more than once, this forces only once
public class JwtTokenVerifier extends OncePerRequestFilter {

    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    public JwtTokenVerifier(JwtConfig jwtConfig, SecretKey secretKey) {
        super();
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        System.out.println("JwtTokenVerifier.doFilterInternal");
        String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());
        System.out.println(authorizationHeader);
        
        // request will be rejected
        if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }
        System.out.println("Authorization header exists: " + authorizationHeader);
        // extract token from Authorization 
        String token = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "");
        try {
            Jws<Claims> claimsJws = Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token);
            
            Claims body = claimsJws.getBody();
            
            String username = body.getSubject();
            var authorities = (List<Map<String, String>>) body.get("authorities");
            
            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
                .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                .collect(Collectors.toSet());
            
            // now user can be authenticated
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username, 
                    null,
                    simpleGrantedAuthorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            
            // the request and response can be passed in the filter chain, otherwise empty response.
            filterChain.doFilter(request, response);
        } catch (JwtException e) {
            throw new IllegalStateException(String.format("Token %s cannot be trusted", token));
        }
        
    }

}
