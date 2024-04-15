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
    
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        return processOAuth2User(oAuth2User, userRequest);
    }
    
    private OAuth2User processOAuth2User(OAuth2User oAuth2User, OAuth2UserRequest userRequest) {
        String email = oAuth2User.getAttribute("email");
        UserCustomer user = userCustomerMapper.findByEmail(email);
        if (user == null) {
            user = new UserCustomer();
            user.setEmail(email);
            user.setName(oAuth2User.getAttribute("name"));
            userCustomerMapper.insertUserCustomer(user);
        } else {
            user.setName(oAuth2User.getAttribute("name"));
            userCustomerMapper.updateUserCustomer(user);
        }
        return oAuth2User;
    }
}
