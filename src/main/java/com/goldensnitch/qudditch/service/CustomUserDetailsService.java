package com.goldensnitch.qudditch.service;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.goldensnitch.qudditch.dto.UserAdmin;
import com.goldensnitch.qudditch.dto.UserCustomer;
import com.goldensnitch.qudditch.dto.UserStore;
import com.goldensnitch.qudditch.mapper.UserAdminMapper;
import com.goldensnitch.qudditch.mapper.UserCustomerMapper;
import com.goldensnitch.qudditch.mapper.UserStoreMapper;

// CustomUserDetailsService 클래스는 Spring Security의 UserDetailsService 인터페이스를 구현하여
// 사용자 인증 정보를 불러오는 역할을 합니다.
@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserCustomerMapper userCustomerMapper;
    private final UserStoreMapper userStoreMapper;
    private final UserAdminMapper userAdminMapper; // 관리자 저장소 추가
    private static final Logger log = LoggerFactory.getLogger(CustomUserDetailsService.class);

    @Autowired
    public CustomUserDetailsService(UserCustomerMapper userCustomerMapper, UserStoreMapper userStoreMapper, UserAdminMapper userAdminMapper) {
        this.userCustomerMapper = userCustomerMapper;
        this.userStoreMapper = userStoreMapper;
        this.userAdminMapper = userAdminMapper; // 관리자 저장소 추가
    }

    // 이메일을 사용하여 사용자를 검색하고, 해당 사용자의 인증 정보를 UserDetails 객체로 반환합니다.
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        log.info("Loading user by email: {}", email);

        UserCustomer customer = userCustomerMapper.findByEmail(email);
        UserStore store = userStoreMapper.findByEmail(email);
        UserAdmin admin = userAdminMapper.findByEmail(email);

        if (customer != null) {
            return createUserDetails(customer);
        } else if (store != null) {
            return createStoreDetails(store);
        } else if (admin != null) {
            return createAdminDetails(admin);
        } else {
            throw new UsernameNotFoundException("User not found with email: " + email);
        }
    }

    private UserDetails createUserDetails(UserCustomer customer) {
        return new ExtendedUserDetails(
            customer.getEmail(),
            customer.getPassword(),
            AuthorityUtils.createAuthorityList("ROLE_CUSTOMER"),
            customer.getId(),
            customer.getName(),
            customer.getEmail(),
            true, true, true, customer.getState() != 2 // assuming 2 is "deleted" or "inactive"
        );
    }

    private UserDetails createStoreDetails(UserStore store) {
        return new ExtendedUserDetails(
            store.getEmail(),
            store.getPassword(),
            AuthorityUtils.createAuthorityList("ROLE_STORE"),
            store.getId(),
            store.getName(),
            store.getEmail(),
            true, true, true, store.getState() != 2
        );
    }

    private UserDetails createAdminDetails(UserAdmin admin) {
        return new ExtendedUserDetails(
            admin.getEmail(),
            admin.getPassword(),
            AuthorityUtils.createAuthorityList("ROLE_ADMIN"),
            admin.getId(),
            admin.getName(),
            admin.getEmail(),
            true, true, true, true // assuming admins are always active
        );
    }
}