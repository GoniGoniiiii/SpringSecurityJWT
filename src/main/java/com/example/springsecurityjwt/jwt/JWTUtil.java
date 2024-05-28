package com.example.springsecurityjwt.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component //컴포넌트 유틸로 관리해줘
public class JWTUtil { //jWt를 검증할 메소드와 jwtUtil을 생성할 메소드를 구현 / 0.12.3
    //jwt에 관해 발급과 검증을 담당하는 클래스
    //Jsontype Web Token
    //Header :  JWT임을 명시, 사용된 암호화 알고리즘
    //Payload : 정보
    //Signature : 암호화 알고리즘(((Base64(Header))+ (Base64(Payload))+암호화키)
    // JWT의 특징은 내부 정보를 단순 BASE64방식으로 인코딩하기때문에 외부에서 쉽게 디코딩할 수 있음
    //외부에서 열람해도 되는 정보를 담아야하며, 토큰 자체의 발급처를 확인하기 위해서 사용
    //(지폐와 같이 외부에서 그 금액을 확인하고 금방 외형을 따라서 만들 수 있지만 발급처에 대한 보장 및 검증은 확실하게 해야 하는 경우에 사용. 따라서 토큰 내부에 비밀번화와 같은 값 입력 금지)

    //JWT암호화 방식
    //암호화 종류 : 양방향 , 단방향
    //- 양방향 : 대칭키, 비대칭키  / 우리는 양방향 대칭키 Hs256 방식을 사용할것임

    //JWTUtil
    //-토큰 Payload에 저장될 정보 : username, role, 생성일, 만료일
    //-JWTUtil 구현 메소드 : JWTUtil 생성자, username 확인 메소드, role 확인 메소드, 만료일 확인 메소드

    //객체키를 저장할  secretkey생성
    private SecretKey secretKey;

    //생성자에서 application.properties에 저장해놓은 키를 불러와서 객체키를 만듦
    public JWTUtil(@Value("${spring.jwt.secret}") String secret){
        this.secretKey=new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    //검증을 진행할 메소드
    public String getUsername(String token){
        //토큰을 암호화가 진행돼있으니 우선 검증해야됨
        //verifywith:  우리가 가지고 있는 secretkey를 넣어서 토큰이 우리 서버에서 생성되었는지,우리가 갖고있는 키와 맞는지 확인후 builder타입으로 리턴해줌
        //parseSignedClaims : 클레임을 확인한대
        //get에서 가져올 타입을 String으로 지정해주면 String 타입의 get username을 진행할 수있때
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username",String.class);
    }

    public String getRole(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get(("role"),String.class);
    }

    public Boolean isExpired(String token){
        //위에  메소드 들과 달리 현재시간을 넣어서 만료된건지 아닌지 확인해줌
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());

    }

    //토큰을 생성하는 메소드
    public String  createJWT(String username,String role, Long expiredMs){
        return Jwts.builder()
                .claim("username",username)
                .claim("role",role)
                .issuedAt(new Date(System.currentTimeMillis())) //현재 발행시간 추가해줌
                .expiration(new Date(System.currentTimeMillis()+expiredMs)) //토큰이 언제 소멸할지
                .signWith(secretKey) //암호화 진행
                .compact();
    }


}
