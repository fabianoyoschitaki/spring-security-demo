package com.example.springsecuritydemo.security;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.springsecuritydemo.auth.ApplicationUserService;
import com.example.springsecuritydemo.jwt.JwtConfig;
import com.example.springsecuritydemo.jwt.JwtTokenVerifier;
import com.example.springsecuritydemo.jwt.JwtUsernameAndPasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter{
    
    
    // PasswordConfig will be injected here
    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;
    
    @Autowired
    public ApplicationSecurityConfig(
            PasswordEncoder passwordEncoder, 
            ApplicationUserService applicationUserService,
            SecretKey secretKey,
            JwtConfig jwtConfig) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//            .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())  // will be unavailable for client side scripts
//            .and()
            .csrf().disable()
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // session won't be stored in the database as it was previously
            .and()
            .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey)) //authenticationManager() comes from WebSecurityConfigurerAdapter
            .addFilterAfter(new JwtTokenVerifier(jwtConfig, secretKey), JwtUsernameAndPasswordAuthenticationFilter.class) // adding this filter after JwtUsernameAndPasswordAuthenticationFilter
            .authorizeRequests()
            .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
            .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
//            THESE WERE REPLACED WITH ANNOTATIONS IN THE CONTROLLER
//            .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(ApplicationUserPermission.STUDENT_WRITE.getPermission())
//            .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(ApplicationUserPermission.STUDENT_WRITE.getPermission())
//            .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(ApplicationUserPermission.STUDENT_WRITE.getPermission())
//            .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())
            .anyRequest()
            .authenticated();
//            WE COMMENTED HTTPBASIC TO REPLACE BY FORMLOGIN
//            .and()
//            .httpBasic();
//            WE COMMENTED FORMLOGIN TO REPLACE BY JWT FILTER
//            .formLogin()
//                .loginPage("/login-page") // we must have a controller to match this
//                .permitAll() // we must allow login page to be public
//                .defaultSuccessUrl("/courses-page", true) // default page
//                .passwordParameter("password") // changing default form name
//                .usernameParameter("username") // changing default form name
//            .and()
//            .rememberMe()
//                .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21)) // defaults to 3 weeks
//                .key("something-very-secured-key")
//                .rememberMeParameter("remember-me") // changing default form name
//            .and()
//            .logout()
//                .logoutUrl("/logout")
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) // only 
//                .clearAuthentication(true)
//                .invalidateHttpSession(true)
//                .deleteCookies("JSESSIONID", "remember-me")
//                .logoutSuccessUrl("/login-page"); // page to which we'll be redirected after logout
    }
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // using the custom authentication provider ApplicationUserService
        auth.authenticationProvider(daoAuthenticationProvider());
    }
    
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        System.out.println("daoAuthenticationProvider");
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }
    
//  using our own implementation of userDetailsService   
//  @Deprecated
//  @Override
//  @Bean
//  protected UserDetailsService userDetailsService() {
//      UserDetails annaSmithUser = User.builder()
//          .username("annasmith")
//          .password(passwordEncoder.encode("password")) // must be encoded
//          .authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())
//          .build();
//      
//      UserDetails lindaUser = User.builder()
//          .username("linda")
//          .password(passwordEncoder.encode("password")) // must be encoded
//          .authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
//          .build();
//      
//      UserDetails tomUser = User.builder()
//          .username("tom")
//          .password(passwordEncoder.encode("password")) // must be encoded
//          .authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
//          .build();
//      
//      return new InMemoryUserDetailsManager(
//          annaSmithUser,
//          lindaUser,
//          tomUser
//      );
//  }

}
