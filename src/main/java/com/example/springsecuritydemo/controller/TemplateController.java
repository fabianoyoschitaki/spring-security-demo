package com.example.springsecuritydemo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import lombok.extern.slf4j.Slf4j;

@Controller
@RequestMapping("/")
@Slf4j
public class TemplateController {
    
    // formLogin will redirect to here. html form action also should be this value
    @GetMapping("login-page")
    public String getLoginView() {
        log.info("getLoginView GET login-page");
        // this must match name of html file inside template
        return "login";
    }
    
    @GetMapping("courses-page")
    public String getCourses() {
        log.info("getCourses GET courses-page");
        // this must match name of html file inside template
        return "courses";
    }
}
