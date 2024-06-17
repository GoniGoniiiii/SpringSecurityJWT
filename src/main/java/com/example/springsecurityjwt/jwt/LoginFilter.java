package com.example.springsecurityjwt.jwt;

import com.example.springsecurityjwt.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Iterator;


public class LoginFilter extends UsernamePasswordAuthenticationFilter{
//로그인 필터 클래스인디 그런데 UsernamePasswordAuthenticationFilter를 상속받은
    
    //주입받기 위해서 생성
    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil=jwtUtil;
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
        //User객체를 알아내기 위해서 customUserDetails객체 생성
        //authentication.getPrincipal() 메소드를 통해서 유저 확인 가능 =>타입오류나기때문에 변경해줘야함
        CustomUserDetails customUserDetails=(CustomUserDetails) authentication.getPrincipal();

        //userName뽑아내기
        String username= customUserDetails.getUsername();

        //userName,role 값을 authentication 객체로부터 뽑아냄
        //뽑아낸 username과 role값을 가지고 jwtUtil에다가 token을 만들어달라고 전달할것임
        Collection<? extends GrantedAuthority> authorities=authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator=authorities.iterator();
        GrantedAuthority auth=iterator.next();

        String role=auth.getAuthority();

        String token=jwtUtil.createJWT(username,role,60*60*10L);
        
        //HTTP 인증방식은 RFC 7235의 정의에 따라 아래와 같은 형태를 가져야한대
        response.addHeader("Authorization","Bearer"+token);

    }

    //로그인 실패시 실행하는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        response.setStatus(401);
    }
}
