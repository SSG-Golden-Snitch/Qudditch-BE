package com.goldensnitch.qudditch.service;

import com.goldensnitch.qudditch.dto.*;
import com.goldensnitch.qudditch.mapper.StoreStockMapper;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class StoreStockService {
    final StoreStockMapper storeStockMapper;

    public StoreStockService(StoreStockMapper storeStockMapper) {
        this.storeStockMapper = storeStockMapper;
    }

    public List<StoreStockRes> selectAllProductByUserStoreId(int userStoreId) {
        return storeStockMapper.selectAllProductByUserStoreId(userStoreId);
    }

    public void updateStock(StoreStock storeStock) {
        storeStockMapper.updateStock(storeStock);
    }

    public StoreStock selectProductByUserStoreIdAndProductId(int userStoreId, int productId) {
        return storeStockMapper.selectProductByUserStoreIdAndProductId(userStoreId, productId);
    }

    public List<StoreStockRes> selectProductByUserStoreIdAndCategoryId(int userStoreId, Integer categoryId) {
        return storeStockMapper.selectProductByUserStoreIdAndCategoryId(userStoreId, categoryId);
    }

    public List<StoreLocQty> getStoreByProductId(String productName, double currentWgs84X, double currentWgs84Y) {
        return storeStockMapper.selectStoreByProductId(productName, currentWgs84X, currentWgs84Y);
    }

    public int cntProductByUserStoreId(int userStoreId) {
        return storeStockMapper.cntProductByUserStoreId(userStoreId);
    }

    public int cntProductByUserStoreIdAndCategoryId(int userStoreId, Integer categoryId) {
        return storeStockMapper.cntProductByUserStoreIdAndCategoryId(userStoreId, categoryId);

    }

    public void insertDisposeLog(int userStoreId, Integer productId, Integer qty) {
        storeStockMapper.insertDisposeLog(userStoreId,productId,qty);
    }

    public int getDisposeLogCount(int userStoreId) {
        return storeStockMapper.getDisposeLogCount(userStoreId);
    }

    public List<DisposeLog> getDisposeLog(int userStoreId) {
        return storeStockMapper.getDisposeLog(userStoreId);
    }
}
