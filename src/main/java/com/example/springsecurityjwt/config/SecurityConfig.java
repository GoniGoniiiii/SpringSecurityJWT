package com.example.springsecurityjwt.config;

import com.example.springsecurityjwt.jwt.JWTFilter;
import com.example.springsecurityjwt.jwt.JWTUtil;
import com.example.springsecurityjwt.jwt.LoginFilter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collection;
import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    //AuthenticationManager가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입

    private final JWTUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration,JWTUtil jwtUtil){
        //SecurityConfig : Spring Security 설정을 구성하는 클래스
        //SecurityConfig 클래스는 AuthenticationConfiguration을 인자로 받는 생성자를 정의
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil=jwtUtil;
    }

    //AuthenticationConfiguration : Spring Security에서 제공하는 구성 클래스 중 하나 , 인증관련 구성을 설정하기위해 사용
    //사용자의 인증방법 및 사용자 정보를 검색하는 방법과 같은 세부적인 사항을 구성하는데 사용
    //Spring Security의 구성을 커스터마이징하고 보안 요구 사항에 맞게 조정하는데 도움
    //ex. 사용자를 인증하기 위해 LDAP서버에서 사용자 정보 가져오기, db에서 사용자 정보를 검색하여 인증하는 방법 설정 등

    //AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        //AuthenticationManager : Spring Security에서 인증을 처리하는 핵심 인터페이스 중 하나
        //사용자의 인증을 수행하고 인증된 사용자의 보안 주체(Principal)를 반환하는 역할
        return configuration.getAuthenticationManager();
        //AuthenticationConfiguration을 사용하여 getAuthenticationManager()메소드를 호출하여 
        //AuthenticationManager 인스턴스를 가져옴
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        //BCryptPasswordEncoder : Spring Security에서 제공하는 클래스 , 안전한 방식으로 사용자의 번호를 해싱하기 위해 사용
        //사용자의 비밀번호를 안전하게 저장하기위해 BCrypt해시 함수를 사용
        //Bcrypt hash 해시 함수 : 단방향 해시 함수, 한 번 해시된 비밀번호는 다시 복구할 수 없음 -> 사용자의 비밀번호가 안전하게 저장
        //해싱 : 비밀번호를 암호화하는 프로세스
        return new BCryptPasswordEncoder();
        //새로운 BCryptPasswordEncoder 인스턴스(객체)를 생성하여 반환
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        //SecurityFilterChain : Spring Security 필터의 체인을 구성하는데 사용
        //HTTP 요청에 대한 보안 설정을 정의하고, 인증 및 권한 부여 처리
        //filterChain() : HttpSecurity 객체를 매개변수로 받음
        //HttpSecurity 객체 : Spring Security의 보안 설정을 구성하는데 사용 /  SecurityFilterChain을 반환 -> Spring Security가 요청을 처리하는 방식
        //ex ) filterChain() 메소드 내에서 http.authorizeRequests()와 같은 메소드를 사용하여 url 패턴에 대한 접근 권한을 설정해 줄 수 있음
        //http.formLogin() or http.oauth2Login()가 같은 메소드를 사용하여 로그인 페이지 및 로그인 방법을 구성할 수 있음.

        //csrf(Cross-Site Request Forgery) : 악의적인 웹사이트를 통해 사용자 인증정보를 탈취하는 공격방법 중 하나
        //csrf disable : session방식에서는 session이 항상 고정되기때문에 csrf 공격이 필수적으로 방어해줘야함
        //jwt(JSON Web Token)방식은 session을 stateLess상태로 관리하기때문에 csrf공격에 대해 방어가 필수적이지않음
        
        //auth: http객체의 메소드들을 호출할때 사용되는 변수 , 'HttpSecurity' 객체를 구성하는 메소드 체인에서 사용됨. 현재 설정중인 보안 구성에 대한 참조.
        //메소드 체인 구조를 유지하면서 Spring Security의 다양한 보안설정을 구성할 수 있도록 함.
        //메소드 체인은 여러 보안 설정을 단계적으로 적용할 수 있도록 해주는데, 각 메소드가 이전 메소드의 결과를 기반으로 동작하기 때문에 'auth' 변수를 통해 설정을 연속적으로 적용할 수 있음.
        //보안 구성을 관리하고 다양한 메소드들을 연결하여 호출하는데 사용되는 중요한 요소이며, 개발자는 이를 통해 복잡한 보안 구성을 보다 쉽게 구현 가능함.

        http
                .cors((cors) -> cors
                        .configurationSource(new CorsConfigurationSource() {
                            @Override
                            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                                CorsConfiguration configuration=new CorsConfiguration();

                                //허용할 프론트엔드쪽 서버에서 데이터를 보낼거기 때문에 3000번대 포트 허용
                                configuration.setAllowedOrigins(Collections.singletonList("localhost:3000"));
                                //허용할 메소드 get,post,등등 모든 메소드 허용
                                configuration.setAllowedMethods(Collections.singletonList("*"));
                                //프론트에서 Credential 설정을 하면 true로 바꿔줘야된대
                                configuration.setAllowCredentials(true);
                                //허용할 헤더
                                configuration.setAllowedHeaders(Collections.singletonList("*"));
                                //시간
                                configuration.setMaxAge(3600L);

                                //백에서 사용자 클라이언트단으로 header를 보내줄때 authorization에 jwt를 넣어서 보내줄거기때문에  authorization header도 허용을 시켜줘야함
                                configuration.setExposedHeaders(Collections.singletonList("Authorization"));


                                return configuration;
                            }
                        }));

        http
                .csrf((auth) -> auth.disable());

        //form Login 인증 방식 disable
        //Spring Security의 기본적인 Form기반 로그인 페이지를 사용하지않도록 설정
        //설정을 하지 않으면? Spring Security가 제공하는 기본 로그인 페이지를 사용하게됨.
        http
                .formLogin((auth) -> auth.disable());

        //http basic 인증 방식 disable
        //HTTP Basic 인증 방식 : 사용자 이름과 비밀번호를 평문으로 전송하는 방식 / 보안에 취약할 수 있음
        http
                .httpBasic((auth) -> auth.disable());

        
        //특정한 경로에 대한 인가 작업
        http
                .authorizeHttpRequests((auth)-> auth     //특정한 경로에 대한 인가작업
                        .requestMatchers("/login","/","join").permitAll() //모든 사용자에게 접근 허용
                       .anyRequest().authenticated());  // 그 외의 모든 요청에 대해서는 인증된 사용자만 접근을 허함 -> 로그인한 사용자에게만 해당 경로에 접근을 허용

        
//        at :원하는 자리에 등록 ,before:해당하는 필터 전에 등록 , after :특정한 필터 이후에 등록
//         LoginFilter는 특정한 인자를 받음  우리가 메소드를 만들때(클래스를 만들때) 생성자 방식으로 AuthenticationManager의 객체를 주입받았음
//        그렇기때문에 SecurityConfig클래스에도 등록을 해줘야됨
//
//        addFilterAt : 지정된 위치에 필터를 추가
        http.addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);


//        LoginFilter를 UsernamePasswordAuthenticationFilter 이전에 추가하고 있음.
//        LoginFilter : 사용자의 로그인을 처리하는 필터 / 사용자가 제출한 로그인 정보를 처리하고 인증을 시도
//        UsernamePasswordAuthenticationFilter : 기본적으로 사용자의 아이디와 비밀번호를 인증하기 위한 Spring Security의 필터
//        로그인 필터가 이전에 추가되므로, 사용자의 로그인 요청이 먼저 처리
        //user
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);



        
        //세션 설정(STATELESS상태로 두는게 중요!)
//        sessionManagement : 세션관리를 구성
//        현재는 Session을 StateLess로 설정 -> 세션을 서버에서 관리하지않고 클라이언트가 모든 필요한 정보를 포함하는 요청을 보내도록 하는것
//        즉 서버는 클라이언트의 상태를 기억하지 않고 각 요청을 독립적으로 처리 / JWT같은 토큰 기반 인증방식에서 주로 사용
//
//        sessionCreationPolicy() : Spring Security에서 세션 생성 정책을 구성하는데 사용 / 세션 관리 방식을 지정하며, 다양한 옵션 설정 가능
//        1. ALWAYS : 항상 세션을 설정(기본값)
//        2. NEVER : 세션을 생성하지 않음
//        3. IF_REQUIRED : 필요할 때만 세션을 생성(기본값)
//        4. STATELESS : 세션을 사용하지 않고, 모든 요청은 서버에 상태르 유지하지 않음.
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        //StateLess옵션을 사용 -> Spring Security는 상태를 유지하지 않고 각 요청을 독립적으로 처리함. 주로 RESTful API 및 토큰 기반 인증과 같은 상황에서 사용됨.
        //jwt를 사용하여 인증하는 경우, 클라이언트는 각 요청에 토큰을 포함하여 서버에 인증을 제공 -> 세션 사용 필요 X
        return http.build();
        //http 객체의 설정을 마치고 이를 적용하여 HttpSecurity를 구성
        //이 HttpSecurity를 반환하여 Spring Security 구성 완료
          }




}
