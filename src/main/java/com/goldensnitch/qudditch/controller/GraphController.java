package com.goldensnitch.qudditch.controller;

import com.goldensnitch.qudditch.dto.graph.SalesGraphDto;
import com.goldensnitch.qudditch.service.GraphService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/graph")
public class GraphController {

    private final GraphService service;

    @Autowired
    public GraphController(GraphService service) {
        this.service = service;
    }

    @GetMapping("/sales")
    // @RequestParam
    public SalesGraphDto getSalesGraph(Integer userStoreId, String yearMonth){
        log.info("GraphController.getSalesGraph: {} {}", userStoreId, yearMonth);

        return service.getSalesGraph(userStoreId, yearMonth);
    }
}