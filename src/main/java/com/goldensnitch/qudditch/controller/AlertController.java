package com.goldensnitch.qudditch.controller;

import com.goldensnitch.qudditch.dto.CustomerAlertLog;
import com.goldensnitch.qudditch.service.AlertService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/customer/alert")
public class AlertController {
    private final AlertService alertService;

    public AlertController(AlertService alertService) {
        this.alertService = alertService;
    }

    @GetMapping("")
    public List<CustomerAlertLog> alertList(int id) {
        return alertService.alertList(id);
    }

    @DeleteMapping("/{id}")
    public int deleteAlert(@PathVariable int id, @RequestBody int userCustomerId) {
            alertService.deleteAlert(id, userCustomerId);
            return 1;
    }


}
