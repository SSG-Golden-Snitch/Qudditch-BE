package com.goldensnitch.qudditch.controller;

import com.goldensnitch.qudditch.dto.SocialLogin;
import com.goldensnitch.qudditch.dto.*;
import com.goldensnitch.qudditch.jwt.JwtTokenProvider;
import com.goldensnitch.qudditch.mapper.UserAdminMapper;
import com.goldensnitch.qudditch.mapper.UserCustomerMapper;
import com.goldensnitch.qudditch.service.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


@RestController
public class AuthenticationController {
    private static final Logger log = LoggerFactory.getLogger(AuthenticationController.class);
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider; // JWT 토큰 제공자 의존성 주입
    private final UserCustomerMapper userCustomerMapper;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final UserAdminMapper userAdminMapper; // 생성자 주입 추가
    @Autowired
    private OCRService ocrService;
    @Autowired
    private TestService testService;

    // @PostMapping("/social-login/{provider}")
    // public ResponseEntity<?> socialLogin(@PathVariable String provider,
    // @RequestBody SocialLoginDto socialLoginDto) {
    // // UserService의 계정 통합 로직 호출
    // ExtendedUserDetails user = (ExtendedUserDetails)
    // userService.processUserIntegration(provider, socialLoginDto);

    // if (user != null) {
    // // 계정 통합 또는 생성 후 성공적으로 처리된 경우, JWT 토큰 발급 및 반환
    // String token = jwtTokenProvider.generateToken(new
    // UsernamePasswordAuthenticationToken(user.getEmail(), null,
    // user.getAuthorities()));
    // return ResponseEntity.ok(new AuthResponse(token));
    // } else {
    // // 처리 중 오류 발생 시
    // return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("계정 처리 중
    // 오류 발생");
    // }
    // }

    @Autowired
    public AuthenticationController(
        AuthenticationManager authenticationManager,
        JwtTokenProvider jwtTokenProvider,
        UserCustomerMapper userCustomerMapper,
        UserService userService,
        PasswordEncoder passwordEncoder,
        UserAdminMapper userAdminMapper // 생성자 주입 추가
    ) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.userCustomerMapper = userCustomerMapper;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.userAdminMapper = userAdminMapper; // 초기화 추가
    }

    // 일반 유저 로그인 처리(http-only쿠키 사용)
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest, HttpServletResponse response,
                                              HttpServletRequest request) {
        // 회원 여부 확인 로직, 비밀번호 검증 로직 추가
        Authentication authentication = authenticationManager
            .authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
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
            .authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        // 토큰 생성 및 반환
        String token = jwtTokenProvider.generateToken(authentication);
        return ResponseEntity.ok(new AuthResponse(token));
    }

    @PostMapping("/social-login/{provider}")
    public ResponseEntity<?> socialLogin(@PathVariable String provider, @RequestBody SocialLogin socialLogin,
                                         HttpServletResponse response) {
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

    @ResponseBody
    @GetMapping("/kakao")
    public ResponseEntity<?> kakaoLogin(@RequestParam("code") String code, HttpServletResponse response) {
        try {
            // 카카오 API를 통해 accessToken 획득
            String accessToken = testService.getAccessToken(code);
            if (accessToken == null) {
                log.error("엑세스 토큰 획득 실패");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("카카오 로그인 실패");
            }

            // 카카오 API에서 받은 accessToken을 이용하여 카카오로부터 유저 정보 획득
            HashMap<String, Object> kakaoUserInfo = testService.getUserInfo(accessToken);
            if (kakaoUserInfo.isEmpty()) {
                log.error("사용자 정보를 가져오는 데 실패했습니다.");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("사용자 정보를 확인할 수 없습니다.");
            }

            // 이메일과 이름을 기준으로 기존사용자 확인 또는 등록
            String email = kakaoUserInfo.get("email").toString();
            // 유저 서비스에 이메일이 등록되어 있는지 확인
            UserCustomer existingUser = userCustomerMapper.findByEmail(email);

            if (existingUser == null) {
                UserCustomer user = new UserCustomer();
                user.setEmail(email);
                user.setPassword(passwordEncoder.encode(RandomStringUtils.randomAlphanumeric(6)));
                user.setName(kakaoUserInfo.get("name").toString());
                user.setState(1); // 사용자 상태를 '일반'(1)으로 설정
                userCustomerMapper.insertUserCustomerKakao(user);
            }

            UserCustomer user = userCustomerMapper.findByEmail(email);

            Test test = new Test(user.getName(), user.getEmail());
            Authentication authentication = new UsernamePasswordAuthenticationToken(test, null,
                AuthorityUtils.createAuthorityList("ROLE_USER"));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwtToken = jwtTokenProvider.generateToken(authentication);

            Cookie cookie = new Cookie("jwt", jwtToken);
            cookie.setHttpOnly(true);
            cookie.setSecure(true); // 프로덕션 환경에서는 true로 설정
            cookie.setPath("/");
            response.addCookie(cookie);

            return ResponseEntity.ok(new AuthResponse(jwtToken));
        } catch (Exception e) {
            log.error("카카오 로그인 처리 중 오류 발생", e);
            return ResponseEntity.ok(Map.of(
                "message", "카카오 로그인에 실패했습니다.",
                "status", "fail"
            ));
        }
    }


    @GetMapping("/loginFailure")
    public String loginFailure() {
        // 로그인 실패 처리
        return "로그인에 실패했습니다.";
    }

    @GetMapping("/verify")
    public ResponseEntity<String> verifyUser(@RequestParam("code") String code) {
        UserCustomer user = userCustomerMapper.findByVerificationCode(code);

        if (user == null) {
            return ResponseEntity.badRequest().body("Invalid verification code.");
        }

        // 사용자 상태를 '일반'(1)으로 업데이트
        user.setState(1);
        user.setVerificationCode(null); // 인증 코드 사용 후 초기화
        userCustomerMapper.updateUserCustomer(user);

        return ResponseEntity.ok("Account verified successfully.");
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
                log.error("Expected principal to be an instance of ExtendedUserDetails but found: {}",
                    principal.getClass().getName());
                // 'principal'이 'ExtendedUserDetails'의 인스턴스가 아닌 경우 처리
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User details not found");
            }
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
        }
    }

    // 이메일 중복 체크
    @PostMapping("/check-email")
    public ResponseEntity<?> checkEmail(@RequestBody Map<String, String> payload) {
        String email = payload.get("email");
        boolean exists = userService.checkEmailExists(email); // 가정한 사용자 이메일 체크 로직
        Map<String, String> response = new HashMap<>();
        if (exists) {
            response.put("message", "이미 사용 중인 이메일입니다.");
        } else {
            response.put("message", "사용 가능한 이메일입니다.");
        }
        return ResponseEntity.ok(response); // JSON 형식으로 반환
    }

    // 이메일 인증 요청 처리
    @PostMapping("/request-verification")
    public ResponseEntity<?> requestVerification(@RequestBody Map<String, String> payload) {
        String email = payload.get("email");
        userService.requestVerification(email);
        return ResponseEntity.ok(Map.of("status", "success"));
    }

    // 계정 인증
    @PostMapping("/verify-account")
    public ResponseEntity<?> verifyAccount(@RequestBody Map<String, String> payload) {
        String email = payload.get("email");
        String code = payload.get("code");
        Map<String, String> response = new HashMap<>();
        UserCustomer user = userCustomerMapper.findByEmail(email);
        if (user != null && code.equals(user.getVerificationCode())) {

            user.setState(1); // 사용자의 상태를 '인증됨'으로 설정
            userCustomerMapper.updateUserCustomer(user);
            response.put("status", "success");
        } else {
            response.put("status", "fail");
        }
        return ResponseEntity.ok(response);
    }

    @PostMapping("/register/customer")
    public ResponseEntity<?> registerCustomer(@RequestBody UserCustomer userCustomer) {
        UserCustomer existingUser = userCustomerMapper.findByEmail(userCustomer.getEmail());

        if (existingUser != null && existingUser.getState() == 1) {
            existingUser.setPassword(passwordEncoder.encode(userCustomer.getPassword()));
            existingUser.setName(userCustomer.getName());
            existingUser.setVerificationCode(null); // 인증 후 코드를 삭제합니다.
            userCustomerMapper.updateUserCustomer(existingUser); // 이메일 인증이 완료된 사용자의 정보를 업데이트합니다.
            return ResponseEntity.ok(Map.of("message", "회원가입이 완료되었습니다", "status", "success"));
        } else {
            return ResponseEntity.ok(Map.of("message", "회원가입에 실패했습니다.", "status", "fail"));
        }
    }

    // 일반 유저 이메일 찾기
    @PostMapping("/find-email")
    public ResponseEntity<?> findEmail(@RequestBody Map<String, String> payload) {
        String name = payload.get("name");
        try {
            String email = userService.findEmailByName(name);
            return ResponseEntity.ok(Collections.singletonMap("email", email));
        } catch (UsernameNotFoundException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("해당 이름으로 등록된 이메일이 없습니다.");
        }
    }

    // 일반 유저 비밀번호 재설정
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> payload) {
        String email = payload.get("email");
        try {
            userService.sendPasswordResetEmail(email);
            return ResponseEntity.ok(Collections.singletonMap("message", "비밀번호 재설정 이메일이 발송되었습니다."));
        } catch (UsernameNotFoundException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("이메일 전송에 실패했습니다.");
        } catch (EmailSendingException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @PostMapping("/business-number")
    public ResponseEntity<?> extractBusinessNumber(@RequestParam("file") MultipartFile file) {
        try {
            String extractedBusinessNumber = ocrService.extractBusinessNumber(file);
            return ResponseEntity.ok(Collections.singletonMap("businessNumber", extractedBusinessNumber));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("OCR 처리 중 오류가 발생했습니다.");
        }
    }

    // 점주 유저 회원가입을 위한 엔드포인트
    @PostMapping("/register/store")
    public ResponseEntity<Map<String, Object>> registerStore(@ModelAttribute RegisterStoreRequest request) {
        try {
            // String extractedBusinessNumber =
            // ocrService.extractBusinessNumber(request.getBusinessLicenseFile());
            //
            // if (!request.getBusinessNumber().equals(extractedBusinessNumber)) {
            // return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("사업자 등록증 번호가 일치하지
            // 않습니다.");
            // }

            // 여기에서 나머지 회원가입 로직을 추가...
            // 예: UserStore 객체 생성 및 userService.registerUserStore 호출
            // 반환된 결과를 ResponseEntity로 감싸서 반환
            UserStore userStore = new UserStore();
            userStore.setStoreId(request.getStoreId());
            userStore.setEmail(request.getEmail());
            userStore.setPassword(request.getPassword());
            userStore.setName(request.getName());
            userStore.setBnNumber(request.getBusinessNumber().replaceAll("-", ""));
            try {
                userService.registerUserStore(userStore);
            } catch (Exception e) {
                return ResponseEntity.ok(Map.of("message", "점주 등록에 실패했습니다.", "status", "fail"));
            }

            return ResponseEntity.ok(Map.of("message", "점주 등록이 완료되었습니다.", "status", "success"));
        } catch (Exception e) {
            // 에러 로깅
            Logger log = LoggerFactory.getLogger(AuthenticationController.class);
            log.error("회원가입 처리 중 오류 발생", e);
            return ResponseEntity.ok(Map.of("message", "점주 등록에 실패했습니다.", "status", "fail"));
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
        Authentication authentication = new UsernamePasswordAuthenticationToken(loginRequest.getEmail(),
            loginRequest.getPassword());
        authentication = authenticationManager.authenticate(authentication);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // JWT 토큰 생성
        String token = jwtTokenProvider.generateToken(authentication);
        AuthResponse authResponse = new AuthResponse(token);

        log.info("Admin authenticated successfully: {}", authResponse);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/request-verification-store")
    public ResponseEntity<Map<String, Object>> requestVerificationStore(@RequestBody Map<String, Object> body)
        throws IOException {
        if (userService.requestVerificationStore(body.get("email").toString())) {
            return ResponseEntity.ok(Map.of("message", "인증 코드가 발송되었습니다.", "status", "success"));
        } else {
            return ResponseEntity.ok(Map.of("message", "인증 코드 발송에 실패했습니다.", "status", "fail"));
        }
    }

    @PostMapping("/verify-store")
    public ResponseEntity<Map<String, Object>> verifyStore(@RequestBody Map<String, Object> payload) {
        if (userService.verifyStore(payload.get("email").toString(), payload.get("code").toString())) {
            return ResponseEntity.ok(Map.of("message", "매장 인증이 완료되었습니다.", "status", "success"));
        } else {
            return ResponseEntity.ok(Map.of("message", "인증 코드가 틀렸습니다.", "status", "fail"));
        }
    }

    @PostMapping("/find-store-email")
    public ResponseEntity<Map<String, Object>> findStoreEmail(@RequestBody Map<String, Object> payload) {
        if (userService.findStoreEmailCnt(payload.get("email").toString()) > 0) {
            return ResponseEntity.ok(Map.of("status", "fail"));
        } else {
            return ResponseEntity.ok(Map.of("status", "succcess"));
        }
    }

}
