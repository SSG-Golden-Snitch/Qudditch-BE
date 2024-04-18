// File: src/main/java/com/goldensnitch/qudditch/repository/UserCustomerRepository.java

package com.goldensnitch.qudditch.mapper;

import com.goldensnitch.qudditch.dto.UserCustomer;
import org.apache.ibatis.annotations.Mapper;

@Mapper // Mybatis 사용 시 @Mapper 어노테이션 사용
public interface UserCustomerMapper {
    UserCustomer selectUserByEmail(String email);

    int insertUserCustomer(UserCustomer user);

    int insertUserCustomerKakao(UserCustomer user);

    UserCustomer findByVerificationCode(String verificationCode);

    int updateUserCustomer(UserCustomer user);

    UserCustomer findByEmail(String email);

    UserCustomer selectUserByName(String name);

    UserCustomer selectUserById(Integer id);

    // 이메일로 사용자의 인증 코드를 업데이트하는 메서드
    void updateVerificationCode(String email, String verificationCode);
}