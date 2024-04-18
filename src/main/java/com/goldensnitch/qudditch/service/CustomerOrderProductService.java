package com.goldensnitch.qudditch.service;

import com.goldensnitch.qudditch.dto.CustomerOrder;
import com.goldensnitch.qudditch.dto.CustomerOrderProduct;
import com.goldensnitch.qudditch.dto.PaginationParam;
import com.goldensnitch.qudditch.dto.payment.OrderProductStoreInfo;
import com.goldensnitch.qudditch.dto.payment.OrderResponse;
import com.goldensnitch.qudditch.mapper.CustomerOrderProductMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class CustomerOrderProductService { // 영수증 정보 생성, 월별 주문내역 확인

    private final CustomerOrderProductMapper customerOrderProductMapper;

    @Autowired
    public CustomerOrderProductService(CustomerOrderProductMapper customerOrderProductMapper) {
        this.customerOrderProductMapper = customerOrderProductMapper;
    }

//    public OrderResponse generateReceipt(Integer orderId) {
//        // 주문 정보 조회
//        CustomerOrder customerOrder = customerOrderProductMapper.findById(orderId);
//        if (customerOrder == null) {
//            throw new RuntimeException("Order not found with ID: " + orderId);
//        }
//        // 해당 주문의 상품 정보 조회
//        List<CustomerOrderProduct> customerOrderProducts = customerOrderProductMapper.findOrderProductsByOrderId(orderId);
//
//        OrderResponse receipt = new OrderResponse();
//        receipt.setCustomerOrder(customerOrder);
//        receipt.setCustomerOrderProducts(customerOrderProducts);
//
//        return receipt;
//    }

    private OrderResponse createOrderResponse(Integer orderId) {
        CustomerOrder customerOrder = customerOrderProductMapper.findById(orderId);
        List<CustomerOrderProduct> customerOrderProducts = customerOrderProductMapper.findOrderProductsByOrderId(orderId);

        OrderResponse orderResponse = new OrderResponse();
        orderResponse.setCustomerOrder(customerOrder);
        orderResponse.setCustomerOrderProducts(customerOrderProducts);

        return orderResponse;
    }

    public List<OrderResponse> getMonthlyOrderHistory(String monthYear, Integer status, PaginationParam paginationParam) {
        List<OrderResponse> orders = customerOrderProductMapper.getMonthlyOrderHistory(monthYear, status, paginationParam.getRecordSize(), paginationParam.getOffset());
        return orders != null ? orders : new ArrayList<>();
    }

    public int countOrdersByMonthYear(String monthYear, Integer status) {
        return customerOrderProductMapper.countOrdersByMonthYear(monthYear, status);
    }

    public List<CustomerOrder> getPointHistoryByCustomerId(Integer userCustomerId) {
        return customerOrderProductMapper.findPointHistoryByCustomerId(userCustomerId);
    }

//    public OrderResponse getDetailedOrderInfo(String partnerOrderId) {
//        return customerOrderProductMapper.findOrderProductsAndStoreInfoByPartnerOrderId(partnerOrderId);
//    }

    public List<OrderProductStoreInfo> getOrderProductsAndStoreInfo(String partnerOrderId) {
        return customerOrderProductMapper.findOrderProductsAndStoreInfoByPartnerOrderId(partnerOrderId);
    }

    public CustomerOrder test(Integer userId) {
        return customerOrderProductMapper.test(userId);
    }

    public List<OrderResponse> findMonthlyOrdersByCustomerId(Integer userCustomerId, String monthYear, Integer status) {
        List<CustomerOrder> customerOrders = customerOrderProductMapper.findMonthlyOrdersByCustomerId(userCustomerId, monthYear, status);
        return customerOrders.stream()
                .map(order -> createOrderResponse(order.getId()))
                .collect(Collectors.toList());
    }


}
