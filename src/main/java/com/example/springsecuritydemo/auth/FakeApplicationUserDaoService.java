package com.example.springsecuritydemo.auth;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.example.springsecuritydemo.security.ApplicationUserRole;
import com.google.common.collect.Lists;

import lombok.extern.slf4j.Slf4j;

// tells Spring it needs to be instantiated and "fake" is the bean to autowire in case there are multiple implementations
@Repository("fake")
@Slf4j
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;
    
    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        log.info("selectApplicationUserByUsername: {}", username);
        return getApplicationUsers()
                .stream()
                .filter(user -> username.equals(user.getUsername()))
                .findFirst();
    }
    
    private List<ApplicationUser> getApplicationUsers() {
        List<ApplicationUser> applicationsUsers = Lists.newArrayList(
                new ApplicationUser(
                        "annasmith", 
                        passwordEncoder.encode("password"),
                        ApplicationUserRole.STUDENT.getGrantedAuthorities(), 
                        true, 
                        true, 
                        true, 
                        true
                ),
                new ApplicationUser(
                        "linda", 
                        passwordEncoder.encode("password"),
                        ApplicationUserRole.ADMIN.getGrantedAuthorities(), 
                        true, 
                        true, 
                        true, 
                        true
                ),
                new ApplicationUser(
                        "tom", 
                        passwordEncoder.encode("password"),
                        ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities(), 
                        true, 
                        true, 
                        true, 
                        true
                )
        );
        return applicationsUsers;
    }

}
