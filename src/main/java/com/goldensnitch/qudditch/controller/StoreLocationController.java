package com.goldensnitch.qudditch.controller;

import com.goldensnitch.qudditch.dto.Pagination;
import com.goldensnitch.qudditch.dto.PaginationParam;
import com.goldensnitch.qudditch.dto.Store;
import com.goldensnitch.qudditch.dto.StoreStockRes;
import com.goldensnitch.qudditch.service.StoreLocationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/store/location")
public class StoreLocationController {
    private final StoreLocationService storeLocationService;
    @Autowired
    public StoreLocationController(StoreLocationService storeLocationService) {
        this.storeLocationService = storeLocationService;
    }

    // 현재위치 값을 넣을 시 근처 스토어
    @GetMapping("")
    public List<Store> getLocation(@RequestParam double currentWgs84X, double currentWgs84Y, Integer limit){
        Map<String, Object> params = new HashMap<>();

        params.put("currentWgs84X", currentWgs84X);
        params.put("currentWgs84Y", currentWgs84Y);
        params.put("limit",limit);

        return storeLocationService.getLocation(params);
    }

    // storeId를 받고 난 userStoreId들의 재고 리스트
    @GetMapping("/stock")
    public Map<String, Object> storeStockList(@RequestParam int userStoreId, PaginationParam paginationParam){

       int storeId = storeLocationService.getUserstoreIdBystoreId(userStoreId);
       int count = storeLocationService.cntStoreStockList(userStoreId);

       List<StoreStockRes> list = storeLocationService.storeStockList(storeId, paginationParam);

       Map<String, Object> map = new HashMap<>();
       map.put("list", list);

       Pagination pagination = new Pagination(count, paginationParam);
       map.put("pagination", pagination);

       return map;
    }
    
}
