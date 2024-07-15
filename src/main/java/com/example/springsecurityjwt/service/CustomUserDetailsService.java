package com.example.springsecurityjwt.service;

import com.example.springsecurityjwt.dto.CustomUserDetails;
import com.example.springsecurityjwt.entity.UserEntity;
import com.example.springsecurityjwt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //db에서 특정 유저를 조회해서 리턴 (그러려면 db연결부터 해줘야됨)
        UserEntity userData=userRepository.findByUsername(username);
        System.out.println(username);
        if(userData != null){
            return new CustomUserDetails(userData);
        }
        return null;
    }
}
