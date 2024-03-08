package com.goldensnitch.qudditch.controller;

import com.goldensnitch.qudditch.dto.CustomerOrder;
import com.goldensnitch.qudditch.service.SalesService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.sql.Date;
import java.util.List;


@Slf4j
@RestController
@RequestMapping("/api/sales")
public class SalesController {

    private final SalesService salesService;

    @Autowired
    public SalesController(SalesService salesService) {
        this.salesService = salesService;
    }

    @GetMapping("/DailySales")
    public List<CustomerOrder> DailySales(@RequestParam String orderedAt) {

        // String으로 받은 날짜데이터를 date타입으로 변환.
        Date date = Date.valueOf(orderedAt);

        List<CustomerOrder> list = salesService.DailySales(date);
        log.info("list: {}", list);
        return list;
    }

    @GetMapping("/MonthlySales")
    public List<CustomerOrder> MonthlySales(CustomerOrder dto) {

        List<CustomerOrder> list = salesService.MonthlySales(dto);
        log.info("list: {}", list);
        return list;
    }
}
