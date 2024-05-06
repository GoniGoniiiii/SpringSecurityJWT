package com.example.springsecurityjwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


public class LoginFilter extends UsernamePasswordAuthenticationFilter{

    //주입받기 위해서 생성
    private final AuthenticationManager authenticationManager;


    public LoginFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {


        //클라이언트 요청해서 username,password 추출
        String username=obtainUsername(request);
        String password=obtainPassword(request);

        System.out.println(username);

        //꺼낸값으로 인증 진행할것임 UsernamePasswordAuthenticationFilter가 autenticationManager한테  username,password를 던져줌
        //그냥 던져주는게 아니고 dto라는 바구니에 담아서 던져주는것임
        //바구니가 UserNamePassowrdauthenticationToken에 username,password를 담아서 최종적으로 authenticationManager한테 전달

        //token객체 생성해서 담음
        UsernamePasswordAuthenticationToken authToken=new UsernamePasswordAuthenticationToken(username,password,null);

        return authenticationManager.authenticate(authToken);

    }

    //로그인 성공시 실행하는 메소드 -> 여기서 jwt 발급하면 됨
    @Override
    protected  void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,Authentication authentication){

    }

    //로그인 실패시 실행하는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {

    }
}
