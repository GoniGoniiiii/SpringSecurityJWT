package com.example.springsecurityjwt.service;

import com.example.springsecurityjwt.dto.JoinDTO;
import com.example.springsecurityjwt.entity.UserEntity;
import com.example.springsecurityjwt.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JoinService {

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public JoinService(UserRepository userRepository,BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder=bCryptPasswordEncoder;
    }

    public void  joinProcess(JoinDTO joinDTO){

        String username= joinDTO.getUsername();
        String password=joinDTO.getPassword();

        //user가 있는지 없는지 확인을 해줘야됨
        Boolean isExist=userRepository.existsByUsername(username);
        if (isExist){
            return ;
        }

        UserEntity data=new UserEntity();
        
        data.setUsername(username);
        data.setPassword(bCryptPasswordEncoder.encode(password)); //password는 암호화를 해줘야됨. 그 메소드는 springConfig에 bean으로 등록해놓았음 불러오자
        data.setRole("ROLE_ADMIN");

        userRepository.save(data);

    }
}
