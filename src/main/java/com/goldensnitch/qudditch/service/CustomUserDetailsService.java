package com.goldensnitch.qudditch.service;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.goldensnitch.qudditch.model.UserCustomer;
import com.goldensnitch.qudditch.repository.UserCustomerRepository;

// CustomUserDetailsService 클래스는 Spring Security의 UserDetailsService 인터페이스를 구현하여
// 사용자 인증 정보를 불러오는 역할을 합니다.
@Service
public class CustomUserDetailsService implements UserDetailsService{
    
    // UserCustomerRepository의 인스턴스를 자동 주입한다.
    @Autowired
    private UserCustomerRepository userCustomerRepository;

    // 이메일을 사용하여 사용자를 검색하고, 해당 사용자의 인증 정보를 UserDetails 객체로 반환합니다.
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        // 이메일을 통해 사용자 정보를 조회한다.
        UserCustomer userCustomer = userCustomerRepository.selectUserByEmail(email);
        if (userCustomer == null) {
            throw new UsernameNotFoundException("User not found with email: " + email);
        }
        // Spring Security의 User 객체를 생성하여 반환한다.
        return new org.springframework.security.core.userdetails.User(userCustomer.getEmail(),
                userCustomer.getPassword(), new ArrayList<>());
    }

}