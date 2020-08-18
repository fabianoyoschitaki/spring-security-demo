package com.example.springsecuritydemo.auth;

import java.util.Collection;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ApplicationUser implements UserDetails {

    private final Set<? extends GrantedAuthority> grantedAuthorities;
    private final String username;
    private final String password;
    private final boolean isAccountNonExpired;
    private final boolean isAccountNonLocked;
    private final boolean isCredentialsNonExpired;
    private final boolean isEnabled;

    public ApplicationUser(String username, String password, Set<? extends GrantedAuthority> grantedAuthorities,
            boolean isAccountNonExpired, boolean isAccountNonLocked, boolean isCredentialsNonExpired,
            boolean isEnabled) {
        super();
        this.grantedAuthorities = grantedAuthorities;
        this.username = username;
        this.password = password;
        this.isAccountNonExpired = isAccountNonExpired;
        this.isAccountNonLocked = isAccountNonLocked;
        this.isCredentialsNonExpired = isCredentialsNonExpired;
        this.isEnabled = isEnabled;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return grantedAuthorities;
    }

    @Override
    public String getPassword() {
        log.info("getPassword: {}", this.password);
        return password;
    }

    @Override
    public String getUsername() {
        log.info("getUsername: {}", this.username);
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        log.info("isAccountNonExpired: {}", this.isAccountNonExpired);
        return isAccountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        log.info("isAccountNonLocked: {}", this.isAccountNonLocked);
        return isAccountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        log.info("isCredentialsNonExpired: {}", this.isCredentialsNonExpired);
        return isCredentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        log.info("isEnabled: {}", this.isEnabled);
        return isEnabled;
    }

}
