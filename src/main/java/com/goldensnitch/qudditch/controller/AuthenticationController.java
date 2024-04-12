package com.goldensnitch.qudditch.controller;


import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.goldensnitch.qudditch.dto.AuthResponse;
import com.goldensnitch.qudditch.dto.LoginRequest;
import com.goldensnitch.qudditch.dto.RegisterRequest;
import com.goldensnitch.qudditch.dto.RegisterStoreRequest;
import com.goldensnitch.qudditch.dto.SocialLoginDto;
import com.goldensnitch.qudditch.dto.UserAdmin;
import com.goldensnitch.qudditch.dto.UserCustomer;
import com.goldensnitch.qudditch.dto.UserStore;
import com.goldensnitch.qudditch.jwt.JwtTokenProvider;
import com.goldensnitch.qudditch.mapper.UserAdminMapper;
import com.goldensnitch.qudditch.mapper.UserCustomerMapper;
import com.goldensnitch.qudditch.service.EmailSendingException;
import com.goldensnitch.qudditch.service.EmailService;
import com.goldensnitch.qudditch.service.ExtendedUserDetails;
import com.goldensnitch.qudditch.service.OCRService;
import com.goldensnitch.qudditch.service.UserService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
@RestController
public class AuthenticationController {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider; // JWT 토큰 제공자 의존성 주입
    private final UserCustomerMapper userCustomerMapper;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final UserAdminMapper userAdminMapper; // 생성자 주입 추가
    private final EmailService emailService;
    private static final Logger log = LoggerFactory.getLogger(AuthenticationController.class);

    @Autowired
    public AuthenticationController(
        AuthenticationManager authenticationManager,
        JwtTokenProvider jwtTokenProvider,
        UserCustomerMapper userCustomerMapper,
        UserService userService,
        EmailService emailService,
        PasswordEncoder passwordEncoder,
        UserAdminMapper userAdminMapper
    ) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.userCustomerMapper = userCustomerMapper;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.userAdminMapper = userAdminMapper; // 초기화 추가
        this.emailService = emailService;
    }

    //일반 유저 로그인 처리(http-only쿠키 사용)
    @PostMapping("/login")
public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest, HttpServletResponse response, HttpServletRequest request) {
    // 회원 여부 확인 로직, 비밀번호 검증 로직 추가
    Authentication authentication = authenticationManager
        .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
    SecurityContextHolder.getContext().setAuthentication(authentication);

    String jwtToken = jwtTokenProvider.generateToken(authentication);

    // HTTP-Only 쿠키 생성 및 설정
    boolean secureCookie = false; // 로컬 환경을 위한 설정 변경
    Cookie cookie = new Cookie("jwt", jwtToken);
    cookie.setHttpOnly(true);
    cookie.setSecure(secureCookie); 
    cookie.setPath("/");
    response.addCookie(cookie);

    // 토큰 대신 간단한 성공 메시지를 선택적으로 반환
    // return ResponseEntity.ok("사용자 인증에 성공했습니다.");
    return ResponseEntity.ok(new AuthResponse(jwtToken));
}

    

    @PostMapping("/store/login")
    public ResponseEntity<?> authenticateStore(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager
            .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        // 토큰 생성 및 반환
        String token = jwtTokenProvider.generateToken(authentication);
        return ResponseEntity.ok(new AuthResponse(token));
    }

    // @PostMapping("/social-login/{provider}")
    // public ResponseEntity<?> socialLogin(@PathVariable String provider, @RequestBody SocialLoginDto socialLoginDto) {
    //     // UserService의 계정 통합 로직 호출
    //     ExtendedUserDetails user = (ExtendedUserDetails) userService.processUserIntegration(provider, socialLoginDto);

    //     if (user != null) {
    //         // 계정 통합 또는 생성 후 성공적으로 처리된 경우, JWT 토큰 발급 및 반환
    //         String token = jwtTokenProvider.generateToken(new UsernamePasswordAuthenticationToken(user.getEmail(), null, user.getAuthorities()));
    //         return ResponseEntity.ok(new AuthResponse(token));
    //     } else {
    //         // 처리 중 오류 발생 시
    //         return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("계정 처리 중 오류 발생");
    //     }
    // }

    @PostMapping("/social-login/{provider}")
public ResponseEntity<?> socialLogin(@PathVariable String provider, @RequestBody SocialLoginDto socialLoginDto, HttpServletResponse response) {
    // 기존의 소셜 로그인 로직...
    String jwtToken = "소셜_로그인_로직으로부터_토큰";

    // HTTP-Only 쿠키 생성 및 설정
    Cookie cookie = new Cookie("jwt", jwtToken);
    cookie.setHttpOnly(true);
    cookie.setSecure(true); // 프로덕션 환경에서 HTTPS를 위해 true로 설정하세요.
    cookie.setPath("/");
    response.addCookie(cookie);

    // 토큰 대신 간단한 성공 메시지를 선택적으로 반환
    return ResponseEntity.ok("소셜 로그인에 성공했습니다.");
}


    @GetMapping("/loginSuccess")
    public String loginSuccess(@AuthenticationPrincipal OAuth2User user) {
        // 로그인 성공 후 사용자 정보 처리
        // 'user' 객체에는 네이버로부터 받은 사용자 정보가 들어 있습니다.
        return "로그인에 성공했습니다.";
    }

    @GetMapping("/loginFailure")
    public String loginFailure() {
        // 로그인 실패 처리
        return "로그인에 실패했습니다.";
    }

    // 일반 유저 회원가입을 위한 엔드포인트
    @PostMapping("/register/customer")
    public ResponseEntity<?> registerCustomer(@RequestBody RegisterRequest registerRequest) {
        UserCustomer userCustomer = new UserCustomer();
        userCustomer.setEmail(registerRequest.getEmail());
        userCustomer.setName(registerRequest.getName());
        userCustomer.setPassword(registerRequest.getPassword()); // 비밀번호는 일단 플레인 텍스트로 설정
    
    
        // 이메일 중복 검사
        UserCustomer existingUser = userCustomerMapper.findByEmail(userCustomer.getEmail());
        if (existingUser != null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("이미 존재하는 이메일입니다.");
        }
        // 비밀번호 암호화 및 사용자 저장
        userCustomer.setPassword(passwordEncoder.encode(userCustomer.getPassword()));
        userCustomerMapper.insertUserCustomer(userCustomer);
        
        return ResponseEntity.ok("회원가입이 완료되었습니다.");
    }

    // 사용자의 이메일 중복 검사를 처리하는 엔드포인트입니다.
    @PostMapping("/check-email")
    public ResponseEntity<?> checkEmail(@RequestBody Map<String, String> requestBody) {
        String email = requestBody.get("email");
        UserCustomer existingUser = userCustomerMapper.findByEmail(email);
        if (existingUser != null) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("이미 사용 중인 이메일입니다.");
        }
        return ResponseEntity.ok("사용 가능한 이메일입니다.");
    }

    // 인증 이메일 보내기
    @PostMapping("/request-verification")
    public ResponseEntity<?> requestEmailVerification(@RequestBody Map<String, String> requestBody) {
        String email = requestBody.get("email");
        // Validation code here...
    
        try {
            // Generate a new verification code and save it to the database.
            UserCustomer newUserCustomer = new UserCustomer();
            // Set newUserCustomer properties including email and verification code.
            userCustomerMapper.insertUserCustomer(newUserCustomer);
    
            emailService.sendVerificationEmail(email, newUserCustomer.getVerificationCode());
            return ResponseEntity.ok("인증 이메일이 발송되었습니다. 이메일을 확인해 주세요.");
        } catch (Exception e) {
            log.error("Failed to send verification email: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("인증 이메일을 보내는 데 실패하였습니다.");
        }
    }

    // 인증 코드를 확인하고 state를 업데이트하는 새로운 메서드입니다.
@PostMapping("/verify-account")
public ResponseEntity<?> verifyAccount(@RequestParam String code) {
    UserCustomer userCustomer = userCustomerMapper.findByVerificationCode(code);
    
    if (userCustomer == null) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("유효하지 않은 인증 코드입니다.");
    }
    
    // 이메일 인증이 성공한 경우, state를 업데이트
    userCustomer.setState(1); // 인증된 상태로 업데이트

    return ResponseEntity.ok("이메일 인증 성공하였습니다.");
}

    @GetMapping("/self")
    public ResponseEntity<?> getSelf(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof ExtendedUserDetails userDetails) {
                Map<String, Object> userInfo = new HashMap<>();
                userInfo.put("id", userDetails.getId());
                userInfo.put("name", userDetails.getName());
                userInfo.put("email", userDetails.getEmail());
                // 기타 상세 정보 추가...
                return ResponseEntity.ok(userInfo);
            } else {
                // 여기서 principal의 실제 클래스 타입을 로깅하여 더 많은 정보를 얻을 수 있습니다.
                log.error("Expected principal to be an instance of ExtendedUserDetails but found: {}", principal.getClass().getName());
                // 'principal'이 'ExtendedUserDetails'의 인스턴스가 아닌 경우 처리
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User details not found");
            }
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
        }
    }

    

    @Autowired
    private OCRService ocrService;


    // 점주 유저 회원가입을 위한 엔드포인트
    @PostMapping("/register/store")
    public ResponseEntity<?> registerStore(@ModelAttribute RegisterStoreRequest request) {
        try {
            String extractedBusinessNumber = ocrService.extractBusinessNumber(request.getBusinessLicenseFile());

            if (!request.getBusinessNumber().equals(extractedBusinessNumber)) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("사업자 등록증 번호가 일치하지 않습니다.");
            }

            // 여기에서 나머지 회원가입 로직을 추가...
            // 예: UserStore 객체 생성 및 userService.registerUserStore 호출
            // 반환된 결과를 ResponseEntity로 감싸서 반환
            UserStore userStore = new UserStore();
            userStore.setStoreId(request.getStoreId());
            userStore.setEmail(request.getEmail());
            userStore.setPassword(request.getPassword());
            userStore.setName(request.getName());
            userStore.setBnNumber(Integer.parseInt(request.getBusinessNumber().replaceAll("-", "")));
            try {
                userService.registerUserStore(userStore);
            } catch (Exception e) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("점주 등록 중 오류가 발생했습니다.");
            }

            return ResponseEntity.ok("점주 등록이 완료되었습니다.");
        } catch (Exception e) {
            // 에러 로깅
            Logger log = LoggerFactory.getLogger(AuthenticationController.class);
            log.error("회원가입 처리 중 오류 발생", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("회원가입 처리 중 오류가 발생했습니다.");
        }
    }

    @GetMapping("/store/search")
    public ResponseEntity<List<UserStore>> searchStores(@RequestParam String name) {
        List<UserStore> stores = userService.searchStoresByName(name);
        return ResponseEntity.ok(stores);
    }

    @PostMapping("/register/admin")
    public ResponseEntity<?> registerAdmin(@RequestBody UserAdmin userAdmin) {
        userService.registerUserAdmin(userAdmin);

        return ResponseEntity.ok("관리자 등록이 완료되었습니다.");
    }

    @PostMapping("/admin/login")
    public ResponseEntity<?> authenticateAdmin(@RequestBody LoginRequest loginRequest) {
        log.info("Attempting to authenticate admin with email: {}", loginRequest.getEmail());

        // 관리자 여부 확인 로직
        UserAdmin admin = userAdminMapper.findByEmail(loginRequest.getEmail());
        if (admin == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("관리자 계정이 존재하지 않습니다.");
        }

        // 비밀번호 검증 로직
        if (!passwordEncoder.matches(loginRequest.getPassword(), admin.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("비밀번호가 틀렸습니다.");
        }

        // 인증 로직
        Authentication authentication =
            new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword());
        authentication = authenticationManager.authenticate(authentication);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // JWT 토큰 생성
        String token = jwtTokenProvider.generateToken(authentication);
        AuthResponse authResponse = new AuthResponse(token);

        log.info("Admin authenticated successfully: {}", authResponse);
        return ResponseEntity.ok(authResponse);
    }

    // 아이디(이메일) 찾기 엔드포인트
@PostMapping("/find-email")
public ResponseEntity<?> findEmail(@RequestBody Map<String, String> payload) {
    String name = payload.get("name");
    try {
        String email = userService.findUsernameByName(name);
        return ResponseEntity.ok(email);
    } catch (UsernameNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("해당 이름의 사용자를 찾을 수 없습니다.");
    }
}

// 비밀번호 재설정 요청 엔드포인트
@PostMapping("/reset-password")
public ResponseEntity<?> resetUserPassword(@RequestBody Map<String, String> payload) {
    String email = payload.get("email");
    try {
        userService.resetPassword(email);
        return ResponseEntity.ok("비밀번호 재설정 이메일을 발송하였습니다.");
    } catch (UsernameNotFoundException | EmailSendingException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
    }
}
}
