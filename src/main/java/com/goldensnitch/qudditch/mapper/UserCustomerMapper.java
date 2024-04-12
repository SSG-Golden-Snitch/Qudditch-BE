// File: src/main/java/com/goldensnitch/qudditch/repository/UserCustomerRepository.java

package com.goldensnitch.qudditch.mapper;

import org.apache.ibatis.annotations.Mapper;

import com.goldensnitch.qudditch.dto.UserCustomer;

@Mapper // Mybatis 사용 시 @Mapper 어노테이션 사용
public interface UserCustomerMapper {
    
    UserCustomer findByEmail(String email);

    UserCustomer findByVerificationCode(String verificationCode);

    void insertUserCustomer(UserCustomer user);

    void updateUserCustomer(UserCustomer user);
    
    void deleteUser(int userId);


    
}