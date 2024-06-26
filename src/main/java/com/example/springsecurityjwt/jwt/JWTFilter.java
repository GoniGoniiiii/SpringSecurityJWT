package com.example.springsecurityjwt.jwt;

import com.example.springsecurityjwt.dto.CustomUserDetails;
import com.example.springsecurityjwt.entity.UserEntity;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
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
        if(authorization == null || !authorization.startsWith("Bearer ")){

            System.out.println("token null");
            filterChain.doFilter(request,response);

            //조건이 해당되면 메소드 종료(필수)
        }

        System.out.println("authorization now");
        System.out.println(authorization);
        //접두사 제거를 위해 띄어쓰기로 앞 뒤 부분을 구분하고 뒷 부분을 token에 저장
        String token=authorization.split(" ")[1];

        //토근 소멸시간 검증
        if(jwtUtil.isExpired(token)){
            System.out.println("token expired");
            filterChain.doFilter(request, response);

            //조건이 해당되면 메소드 종료(필수)ㄴ
            return ;
//            try{
//                jwtUtil.isExpired(token);
//            }catch (ExpiredJwtException e){
//                System.out.println("token expired");
//                filterChain.doFilter(request,response);
//                return;
//            }
        }

        //토큰에서 username과 role획득
        String username=jwtUtil.getUsername(token);
        String role=jwtUtil.getRole(token);


        //userEntity를 생성하여 값 set
        UserEntity userEntity=new UserEntity();
        userEntity.setUsername(username);
        //비밀번호의 값은 토큰에 담겨있지않음 그렇지만 초기화는 해줘야됨
        //비밀번호는 요청이 올때마다 db에서 조회하지않게 임시로 간단하게 넣어줌 -> 부하와서 속도느려질까봐 그런듯
        userEntity.setPassword("temppassword");
        userEntity.setRole(role);

        //UserDetails에 회원 정보 객체 담기
        CustomUserDetails customUserDetails= new CustomUserDetails(userEntity);

        //스프링 시큐리티 인증 토큰 생성
        Authentication authToken= new UsernamePasswordAuthenticationToken(customUserDetails,null,customUserDetails.getAuthorities());

        //세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request,response);





    }
}
