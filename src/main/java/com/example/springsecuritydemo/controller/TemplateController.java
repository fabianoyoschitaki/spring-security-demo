package com.example.springsecuritydemo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class TemplateController {
    
    // formLogin will redirect to here. html form action also should be this value
    @GetMapping("login-page")
    public String getLoginView() {
        // this must match name of html file inside template
        return "login";
    }
    
    @GetMapping("courses-page")
    public String getCourses() {
        // this must match name of html file inside template
        return "courses";
    }
}
