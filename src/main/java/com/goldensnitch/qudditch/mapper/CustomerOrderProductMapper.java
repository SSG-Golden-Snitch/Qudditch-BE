package com.goldensnitch.qudditch.mapper;

import com.goldensnitch.qudditch.dto.CustomerOrder;
import com.goldensnitch.qudditch.dto.CustomerOrderProduct;
import com.goldensnitch.qudditch.dto.payment.OrderProductStoreInfo;
import com.goldensnitch.qudditch.dto.payment.OrderResponse;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;
import java.util.Map;

@Mapper
public interface CustomerOrderProductMapper  {
    void insertCustomerOrder(CustomerOrder customerOrder);

    void insertCustomerOrderProduct(CustomerOrderProduct customerOrderProduct);

    // CustomerOrder findById(int id);

    List<CustomerOrder> findByUserCustomerId(String monthYear);

    List<CustomerOrder> findByMonthYear(String monthYear, Integer status);

    CustomerOrder findById(int customerOrderId);

    CustomerOrder findByPartnerOrderId(String partnerOrderId);

    void update(CustomerOrder order);

    CustomerOrder findByTid(String tid);

    List<CustomerOrderProduct> findOrderProductsByOrderId(int customerOrderId);

    // 사용자 ID로 포인트 사용 및 적립 내역 조회
    List<CustomerOrder> findPointHistoryByCustomerId(Integer userCustomerId);

    void updateOrderStatus(@Param("tid") Map<String, Object> tid);

    List<OrderProductStoreInfo> findOrderProductsAndStoreInfoByPartnerOrderId(String partnerOrderId);

    CustomerOrder test(Integer userId);

    List<CustomerOrder> findMonthlyOrdersByCustomerId(Integer userCustomerId, String monthYear, Integer status);

    int countOrdersByMonthYear(String monthYear, Integer status);

    List<OrderResponse> getMonthlyOrderHistory(String monthYear, Integer status, Integer recordSize, Integer offset);

}
