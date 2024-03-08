package com.goldensnitch.qudditch.service;

import com.goldensnitch.qudditch.dto.CustomerOrder;
import com.goldensnitch.qudditch.mapper.SalesMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.sql.Date;
import java.util.List;

@Service
public class SalesService {

    private final SalesMapper salesMapper;
    
    @Autowired
    public SalesService(SalesMapper salesMapper) {
        this.salesMapper = salesMapper;
    }


    public List<CustomerOrder> DailySales(Date date) {

        return salesMapper.DailySales(date);
    }

    public List<CustomerOrder> MonthlySales(CustomerOrder dto) {

        return salesMapper.MonthlySales(dto);
    }

}
