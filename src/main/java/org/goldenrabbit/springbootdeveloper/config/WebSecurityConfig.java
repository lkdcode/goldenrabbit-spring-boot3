package org.goldenrabbit.springbootdeveloper.config;

import lombok.RequiredArgsConstructor;
import org.goldenrabbit.springbootdeveloper.service.UserDetailService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@RequiredArgsConstructor
@Configuration
public class WebSecurityConfig {

    private final UserDetailService userService;

    @Bean // 스프링 시큐리티 기능 비활성화
    public WebSecurityCustomizer configure() {
        return (web) -> web.ignoring()
                .requestMatchers(toH2Console())
                .requestMatchers("/static/**")
                ;
    }

    @Bean // 특정 HTTP 요청에 대한 웹 기반 보안 구성
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeRequests()// 인증, 인가 설정
                .requestMatchers("/login", "/signup", "/user").permitAll() // 특정 요청과 일치하는 url에 대한 액세스를 설정한다.
                // permitAll 은 인증/인가 없이도 접근을 허용
                .anyRequest().authenticated() // 별도의 인가는 필요하지 않지만 인증이 접근 할 수 있습니다.
                .and()
                .formLogin() // 폼 기반 로그인 설정
                .loginPage("/login") // 로그인 페이지 경로 설정
                .defaultSuccessUrl("/articles") // 로그인이 완료되었을 때 이동할 경로 설정
                .and()
                .logout() // 로그아웃 설정
                .logoutSuccessUrl("/login") // 로그아웃이 완료되었을 때 이동할 경로 설정
                .invalidateHttpSession(true) // 로그아웃 이후에 세션을 전체 삭제할지 여부를 설정
                .and()
                .csrf().disable() // csrf 비활성화
                .build();
    }

    @Bean // 인증 관리자 관련 설정
    public AuthenticationManager authenticationManager( // 사용자 정보를 가져올 서비스를 재정의하건, 인증 방법, 예를 들어 LDAP, JDBC 기반 인증 등을 설정
                                                        HttpSecurity http,
                                                        BCryptPasswordEncoder bCryptPasswordEncoder,
                                                        UserDetailService userDetailService
    ) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(userService) // 사용자 정보를 가져올 서비스를 설정, 이 때 반드시 UserDetailsService 를 구현해야함
                .passwordEncoder(bCryptPasswordEncoder) // 비밀번호 암호화를 위한 인코더 설정
                .and()
                .build();
    }

    @Bean // 패스워드 인코더로 사용할 빈 등록
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
