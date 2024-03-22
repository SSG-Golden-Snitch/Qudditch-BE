package com.goldensnitch.qudditch.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.goldensnitch.qudditch.dto.AuthResponse; // 실제 경로에 맞게 수정 필요
import com.goldensnitch.qudditch.dto.LoginRequest; // 실제 경로에 맞게 수정 필요
import com.goldensnitch.qudditch.dto.SocialLoginDto;
import com.goldensnitch.qudditch.dto.UserCustomer;
import com.goldensnitch.qudditch.jwt.JwtTokenProvider; // 가정한 패키지 경로, 실제 경로에 맞게 수정 필요
import com.goldensnitch.qudditch.repository.UserCustomerRepository;

@RestController
public class AuthenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenProvider jwtTokenProvider; // JWT 토큰 제공자 의존성 주입

    @Autowired
    private UserCustomerRepository userCustomerRepository;


    private static final Logger log = LoggerFactory.getLogger(AuthenticationController.class);
    

    @PostMapping("/login")
public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
    log.info("Attempting to authenticate user with email: " + loginRequest.getEmail());

    // 회원 여부 확인 로직
    UserCustomer user = userCustomerRepository.findByEmail(loginRequest.getEmail());
    if (user == null) {
        return ResponseEntity
            .status(HttpStatus.UNAUTHORIZED)
            .body("회원가입이 필요합니다.");
    }

    // 자격 증명이 올바르면, Spring Security Context에 인증 정보를 설정
    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
    SecurityContextHolder.getContext().setAuthentication(authentication);

    // JWT 토큰 생성
    String token = jwtTokenProvider.generateToken(authentication);

    // 생성된 토큰을 클라이언트에 반환
    return ResponseEntity.ok(new AuthResponse(token));
}


    @PostMapping("/store/login")
    public ResponseEntity<?> authenticateStore(@RequestBody LoginRequest loginRequest) {
        log.info("Attempting to authenticate store with email: " + loginRequest.getEmail());
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        // 토큰 생성 및 반환
        String token = jwtTokenProvider.generateToken(authentication);
        return ResponseEntity.ok(new AuthResponse(token));
    }

    // 소셜 로그인 및 이메일 인증 통합을 위한 컨트롤러 메소드 추가
    @PostMapping("/social-login/naver")
    public ResponseEntity<?> socialLogin(@RequestBody SocialLoginDto  socialLoginDto) {
        // 네이버 소셜 로그인 후 받은 정보를 처리하는 로직을 구현
        // 이 때, 필요한 정보를 DTO로부터 받아오고 처리 결과를 반환합니다.
        // 예시로 AuthResponse를 사용하여 토큰과 함께 응답
        String token = "가상의 토큰"; // 이 부분은 실제 로직에 따라 생성된 토큰으로 대체해야 합니다.
        return ResponseEntity.ok(new AuthResponse(token));
    }

    @GetMapping("/loginSuccess")
    public ResponseEntity<String> loginSuccess(@AuthenticationPrincipal OAuth2User user) {
        // 로그인 성공 후 사용자 정보 처리 로직
        // 리다이렉트 대신 성공 메시지 반환
        return ResponseEntity.ok("로그인에 성공했습니다.");
    }
    
    @GetMapping("/loginFailure")
    public ResponseEntity<String> loginFailure() {
        // 로그인 실패 처리 로직
        // 리다이렉트 대신 실패 메시지 반환
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("로그인에 실패했습니다.");
    }

    @GetMapping("/verify")
    public ResponseEntity<String> verifyUser(@RequestParam("code") String code) {
        UserCustomer user = userCustomerRepository.findByVerificationCode(code);

        if (user == null) {
            return ResponseEntity.badRequest().body("Invalid verification code.");
        }

        // 사용자 상태를 '일반'(1)으로 업데이트
        user.setState(1);
        user.setVerificationCode(null); // 인증 코드 사용 후 초기화
        userCustomerRepository.updateUserCustomer(user);

        return ResponseEntity.ok("Account verified successfully.");
    }
}
