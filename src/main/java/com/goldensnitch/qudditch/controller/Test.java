package com.goldensnitch.qudditch.controller;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.security.Principal;

@Data
@AllArgsConstructor
public class Test implements Principal {
    private String name;
    private String email;

    @Override
    public String getName() {
        return name;
    }
}