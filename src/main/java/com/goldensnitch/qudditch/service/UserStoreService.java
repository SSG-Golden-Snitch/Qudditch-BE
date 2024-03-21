package com.goldensnitch.qudditch.service;

import com.goldensnitch.qudditch.mapper.UserStoreMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserStoreService {

    @Autowired
    private UserStoreMapper userStoreMapper;

    // 사용자가 선택한 가게의 store_id를 받아 유효성 확인 후 user_store_id 반환
    public Integer selectUserStore(Integer storeId) {
        Integer userStoreId = findUserStoreIdByStoreId(storeId);
        if (userStoreId != null && validateUserStoreId(userStoreId)) {
            return userStoreId;
        }
        else{
            return null;
        }
    }

    // store_id에 대응하는 user_store_id를 조회
    public Integer findUserStoreIdByStoreId(Integer storeId) {
        return userStoreMapper.findUserStoreIdByStoreId(storeId);
    }

    // 주어진 user_store_id가 유효한지 확인
    public boolean validateUserStoreId(Integer userStoreId){
        Integer count = userStoreMapper.countUserStoreById(userStoreId); // 아이디 개수 반환
        return count != null && count > 0;
    }

}
