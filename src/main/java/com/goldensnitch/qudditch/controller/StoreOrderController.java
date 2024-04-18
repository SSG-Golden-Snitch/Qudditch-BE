package com.goldensnitch.qudditch.controller;

import com.goldensnitch.qudditch.dto.Pagination;
import com.goldensnitch.qudditch.dto.PaginationParam;
import com.goldensnitch.qudditch.dto.StoreOder.OrderDetailWithProducts;
import com.goldensnitch.qudditch.dto.StoreOder.ProductWithDetailQty;
import com.goldensnitch.qudditch.dto.StoreOder.ProductWithQty;
import com.goldensnitch.qudditch.dto.StoreOrder;
import com.goldensnitch.qudditch.dto.StoreOrderProduct;
import com.goldensnitch.qudditch.service.ExtendedUserDetails;
import com.goldensnitch.qudditch.service.StoreOrderService;
import lombok.extern.slf4j.Slf4j;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Slf4j
@RestController
@RequestMapping("/api/store/order")
public class StoreOrderController {
    private final StoreOrderService storeOrderService;

    @Autowired
    public StoreOrderController(StoreOrderService storeOrderService) {
        this.storeOrderService = storeOrderService;
    }

    @GetMapping("")
    public Map<String, Object> orderList(@AuthenticationPrincipal ExtendedUserDetails userDetails, PaginationParam paginationParam) {

        int userStoreId = userDetails.getId();
        // 제품리스트
        List<StoreOrder> orderList = storeOrderService.orderList(userStoreId,paginationParam);
        // 총 수
        int count = storeOrderService.cntOrderList(userStoreId);

        Map<String, Object> map = new HashMap<String, Object>();
        map.put("orderList", orderList);

        Pagination pagination = new Pagination(count, paginationParam);
        map.put("pagination", pagination);

        if (orderList == null) {
            map.put("message", "목록이 없습니다");
        } else {
            map.put("message", "발주리스트 불러오기 성공!");
        }
        return map;
    }

    @PostMapping("")
    public ResponseEntity<Map<String, String>> insertOrder(@AuthenticationPrincipal ExtendedUserDetails userDetails, @RequestBody List<ProductWithQty> products) {
        int storeId = userDetails.getId();
        System.out.println(storeId);

        try {
            StoreOrder storeOrder = new StoreOrder();
            storeOrder.setUserStoreId(storeId);
            storeOrderService.insertOrder(storeOrder);

            // storeId 값을 들고와서 변수에 저장
            int orderId = storeOrderService.getStoreId();

            // 제품아이디와 개수를 store_order_product에 저장
            for (ProductWithQty product : products) {
                StoreOrderProduct storeOrderProduct = new StoreOrderProduct();
                storeOrderProduct.setOrderStoreId(orderId);
                storeOrderProduct.setProductId(product.getProductId());
                storeOrderProduct.setQty(product.getQty());

                storeOrderService.insertId(storeOrderProduct);
            }
            return ResponseEntity.ok().body(Map.of("message", "주문이 성공적으로 추가되었습니다."));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest().body(Map.of("message", "주문이 추가되지 않았습니다."));
        }
    }


    @GetMapping("/detail/{id}")
    public ResponseEntity<OrderDetailWithProducts> listDetail(@PathVariable int id) {
        try {
            log.info("StoreOrderController.listDetail: {}", id);

            // 주문 상세 정보 조회
            StoreOrder storeOrder = storeOrderService.getStoreOrderById(id);
            if (storeOrder == null) {
                return ResponseEntity.notFound().build(); // 주문이 없는 경우 404
            }

            // 주문에 대한 제품 상세 정보 조회
            List<ProductWithDetailQty> productWithDetailQty = storeOrderService.getProductWithQty(storeOrder.getId());

            // 조회된 정보를 포함한 응답 반환
            return ResponseEntity.ok(new OrderDetailWithProducts(storeOrder, productWithDetailQty));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(null); // 서버 오류 500
        }
    }

    // 생성된 엑셀 파일을 저장할 경로 지정
//    @Value("${excel.file.directory}")
//    private String excelFileDirectory;

    @GetMapping("/download/{id}")
    public ResponseEntity<ByteArrayResource> downloadOrderDataAsExcel(@PathVariable int id) {
        try {
            // 주문 데이터를 검색하고 엑셀 파일을 생성
            StoreOrder storeOrder = storeOrderService.getStoreOrderById(id);
            List<ProductWithDetailQty> productWithDetailQty = storeOrderService.getProductWithQty(storeOrder.getId());
            byte[] excelBytes = createExcelFile(storeOrder, productWithDetailQty);

            // 생성된 엑셀 파일을 서버 파일 시스템의 특정 위치에 저장
//            String fileName = "Product order from " + id + ".xlsx";
//            String filePath = excelFileDirectory + File.separator + fileName;
//            saveExcelFile(excelBytes, filePath);

            // 다운로드를 위해 파일을 준비
            ByteArrayResource resource = new ByteArrayResource(excelBytes);
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=");
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);

            return ResponseEntity.ok()
                    .headers(headers)
                    .contentLength(excelBytes.length)
                    .body(resource);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).build(); // 서버 오류 500
        }
    }

    private byte[] createExcelFile(StoreOrder storeOrder, List<ProductWithDetailQty> productWithDetail) {

        Workbook workbook = new XSSFWorkbook();
        Sheet sheet = workbook.createSheet("발주서");

        // 헤더 추가
        Row headerRow = sheet.createRow(0);
        headerRow.createCell(0).setCellValue("Order ID");
        headerRow.createCell(1).setCellValue("브랜드");
        headerRow.createCell(2).setCellValue("제품명");
        headerRow.createCell(3).setCellValue("수량");

        // 데이터 추가
        for (int i = 0; i < productWithDetail.size(); i++) {
            Row dataRow = sheet.createRow(1 + i);
            dataRow.createCell(0).setCellValue(storeOrder.getId());
            dataRow.createCell(1).setCellValue(productWithDetail.get(i).getBrand());
            dataRow.createCell(2).setCellValue(productWithDetail.get(i).getName());
            dataRow.createCell(3).setCellValue(productWithDetail.get(i).getQty());
        }
        // 엑셀 파일을 byte 배열로 변환
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            workbook.write(outputStream);
            workbook.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return outputStream.toByteArray();
    }

//    private void saveExcelFile(byte[] excelBytes, String filePath) {
//        File file = new File(filePath);
//        try (FileOutputStream fos = new FileOutputStream(file)) {
//            fos.write(excelBytes);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }


    @PostMapping("/detail/update/{id}")
    public ResponseEntity<String> updateOrderProducts(@PathVariable int id, @RequestBody List<ProductWithQty> updateProducts) {

        // 기존 주문 정보
        StoreOrder storeOrder = storeOrderService.getStoreOrderById(id);
        if (storeOrder == null) {
            return ResponseEntity.badRequest().body("id확인하세용");
        }
        // 발주상태가 "대기"가 아니면 업데이트 거부
        if (!storeOrder.getState().equals("대기")) {
            return ResponseEntity.badRequest().body("대기중인 발주만 수정 가능합니다");
        }

        for (ProductWithQty updatedProduct : updateProducts) {
            // 제품아이디가 없으면 제품 insert , 제품아이디가 있으면 update
            if (storeOrderService.cntProductByStoreOrder(id, updatedProduct.getProductId()) == 0) {

                StoreOrderProduct newProducts = new StoreOrderProduct();

                newProducts.setOrderStoreId(storeOrder.getId());
                newProducts.setProductId(updatedProduct.getProductId());
                newProducts.setQty(updatedProduct.getQty());
                // 업데이트
                storeOrderService.insertId(newProducts);
            }else{
                StoreOrderProduct storeOrderProduct = new StoreOrderProduct();

                storeOrderProduct.setOrderStoreId(storeOrder.getId());
                storeOrderProduct.setProductId(updatedProduct.getProductId());
                storeOrderProduct.setQty(updatedProduct.getQty());
                // 업데이트
                storeOrderService.updateOrderProducts(storeOrderProduct);

            }
        }
        // 업데이트 후 수량이 0인 경우 제거
        for (ProductWithQty product : updateProducts) {
            if (product.getQty() == 0) {
                storeOrderService.removeProduct(product.getProductId(), id);
            }
        }
        return ResponseEntity.ok("수정성공!!");
    }


}
