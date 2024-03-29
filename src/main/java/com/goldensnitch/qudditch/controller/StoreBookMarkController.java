package com.goldensnitch.qudditch.controller;

import com.goldensnitch.qudditch.dto.CustomerBookmarkStore;
import com.goldensnitch.qudditch.dto.StoreBookmark.BookmarkReq;
import com.goldensnitch.qudditch.service.StoreBookMarkService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("api/store/bookmark")
public class StoreBookMarkController {
    private final StoreBookMarkService storeBookMarkService;

    @Autowired
    public StoreBookMarkController(StoreBookMarkService storeBookMarkService) {
        this.storeBookMarkService = storeBookMarkService;
    }

    @PostMapping("/toggle")
    public String toggleStoreBookmark(@RequestBody BookmarkReq request) {
        return storeBookMarkService.toggleStoreBookmark(request.getUserCustomerId(), request.getStoreId());
    }

    @GetMapping("")
    public List<CustomerBookmarkStore> getStoreBookmarks() {
        int userCustomerId = 2;
        return storeBookMarkService.bookmarkList(userCustomerId);
    }




}