package com.goldensnitch.qudditch.dto;

import lombok.Data;

import java.sql.Date;

@Data
public class StoreVisitorDaily {
    private Integer id;
    private Integer userStoreId;
    private Date ymd;
    private Integer cnt;
}
