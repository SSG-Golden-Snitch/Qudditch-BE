package com.goldensnitch.qudditch.controller;

import com.goldensnitch.qudditch.dto.CustomerOrder;
import com.goldensnitch.qudditch.dto.Pagination;
import com.goldensnitch.qudditch.dto.PaginationParam;
import com.goldensnitch.qudditch.dto.payment.OrderProductStoreInfo;
import com.goldensnitch.qudditch.dto.payment.OrderResponse;
import com.goldensnitch.qudditch.service.CustomerOrderProductService;
import com.goldensnitch.qudditch.service.ExtendedUserDetails;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/order")
public class CustomerOrderProductController {

    private final CustomerOrderProductService customerOrderProductService;

    public CustomerOrderProductController(CustomerOrderProductService customerOrderProductService) {
        this.customerOrderProductService = customerOrderProductService;
    }

    @GetMapping("/receipt")
    public ResponseEntity<List<OrderProductStoreInfo>> getOrderDetails(@RequestParam String partnerOrderId) {
        List<OrderProductStoreInfo> details = customerOrderProductService.getOrderProductsAndStoreInfo(partnerOrderId);
        if (details.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(details);
    }

    // getId 변경 - 03.29
    @GetMapping("/history")
    public Map<String, Object> getMonthlyOrderHistory(@RequestParam String monthYear, @RequestParam Integer status,
                                                      PaginationParam paginationParam) {
            // 주문리스트
            List<OrderResponse> history = customerOrderProductService.getMonthlyOrderHistory(monthYear, status, paginationParam);

            // 총 수
            int count = customerOrderProductService.countOrdersByMonthYear(monthYear, status);

            Map<String, Object> map = new HashMap<>();
            map.put("history", history);

            Pagination pagination = new Pagination(count, paginationParam);
            map.put("pagination", pagination);

            if (history == null) {
                map.put("message", "목록이 없습니다");
            } else {
                map.put("message", "판매내역 불러오기 성공!");
            }
        return map;
    }

    @GetMapping("/history/c")
    public ResponseEntity<List<OrderResponse>> getUserMonthlyOrderHistory(@AuthenticationPrincipal ExtendedUserDetails userDetails, @RequestParam String monthYear, @RequestParam Integer status) {
        try {
            int userCustomerId = userDetails.getId();

            List<OrderResponse> history = customerOrderProductService.findMonthlyOrdersByCustomerId(userCustomerId, monthYear, status);
            if (history.isEmpty()) {
                return ResponseEntity.noContent().build();
            }
            return ResponseEntity.ok(history);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(null);
        }
    }

    @GetMapping("/history/point")
    public ResponseEntity<List<CustomerOrder>> getPointHistoryByCustomerId(@AuthenticationPrincipal ExtendedUserDetails userDetails) {
        try {
            int userCustomerId = userDetails.getId();

            List<CustomerOrder> pointHistory = customerOrderProductService.getPointHistoryByCustomerId(userCustomerId);
            return ResponseEntity.ok(pointHistory);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(null);
        }
    }
}