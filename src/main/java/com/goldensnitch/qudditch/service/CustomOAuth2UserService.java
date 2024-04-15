package com.goldensnitch.qudditch.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.goldensnitch.qudditch.dto.UserCustomer;
import com.goldensnitch.qudditch.mapper.UserCustomerMapper;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    @Autowired
    private UserCustomerMapper userCustomerMapper;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    // OAuth2User 정보 로드
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        return processOAuth2User(oAuth2User, userRequest);
    }
    
    // 로드된 사용자 정보를 처리
    private OAuth2User processOAuth2User(OAuth2User oAuth2User, OAuth2UserRequest userRequest) {
        String email = oAuth2User.getAttribute("email");  // 이메일 속성 추출
        UserCustomer user = userCustomerMapper.findByEmail(email);
        if (user == null) {
            user = new UserCustomer();
            user.setEmail(email);
            user.setName(oAuth2User.getAttribute("name"));  // 이름 속성 추출
            userCustomerMapper.insertUserCustomer(user);  // DB에 사용자 정보 삽입
        } else {
            user.setName(oAuth2User.getAttribute("name"));
            userCustomerMapper.updateUserCustomer(user);  // 기존 사용자 정보 업데이트
        }
        return oAuth2User;
    }
}
