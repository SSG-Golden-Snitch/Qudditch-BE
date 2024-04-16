package com.goldensnitch.qudditch.controller;

import com.goldensnitch.qudditch.service.TestService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequiredArgsConstructor
@RequestMapping("/login")
@Slf4j
public class TestController {
    private final TestService testService;

    @ResponseBody
    @GetMapping("/kakao")
    public ResponseEntity<?> login(@RequestParam("code") String code, HttpServletResponse response) throws URISyntaxException {
        String res = "accesstoken 생성 완료";
        System.out.println("code :" + code); //파라미터로 받아온 code 확인
        String access_Token = testService.getAccessToken(code); // code를 이용해 카카오 엑세스 토큰을 발급받음
        HashMap<String, Object> userInfo = testService.getUserInfo(access_Token); //발급받은 엑세스 토큰으로 유저정보 가져옴
        System.out.println("userInfo = " + userInfo);

        // 회원 인지확인 (개인상황에 맞게 구현)
//        userService.check(userInfo.get("email").toString(), userInfo.get("nickname").toString());
//        return userService.kakaoLogin(userInfo.get("email").toString(), response);
        return ResponseEntity.ok(Map.of("res", userInfo));
    }

}