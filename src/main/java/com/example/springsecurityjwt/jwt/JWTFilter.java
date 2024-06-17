package com.example.springsecurityjwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTFilter  extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //token검증

        //request에서 Authrization  헤더를 찾음
        String authorization=request.getHeader("Authorization");

        //Authorization 헤더 검증(null인지 아닌지)
        if(authorization == null || !authorization.startsWith("Bearer")){

            System.out.println("token null");
            filterChain.doFilter(request,response);

            //조건이 해당되면 메소드 종료(필수)
        }

        //접두사 제거를 위해 띄어쓰기로 앞 뒤 부분을 구분하고 뒷 부분을 token에 저장
        String token=authorization.split(" ")[1];

        //토근 소멸시간 검증
        if(jwtUtil.isExpired(token)){


        }

        

    }
}
