// package com.goldensnitch.qudditch.config;

// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
// import org.springframework.security.web.SecurityFilterChain;
// import org.springframework.web.client.RestTemplate;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

//     private final UserDetailsService userDetailsService;
//     private final ClientRegistrationRepository clientRegistrationRepository;

//     public SecurityConfig(UserDetailsService userDetailsService, ClientRegistrationRepository clientRegistrationRepository) {
//         this.userDetailsService = userDetailsService;
//         this.clientRegistrationRepository = clientRegistrationRepository;
//     }

//     @Bean
//     public PasswordEncoder passwordEncoder() {
//         return new BCryptPasswordEncoder();
//     }

//     // AuthenticationManagerBuilder를 사용하여 AuthenticationManager 빈을 생성합니다.
//     @Bean
//     public AuthenticationManager authenticationManager(AuthenticationManagerBuilder auth) throws Exception {
//         auth.userDetailsService(userDetailsService)
//             .passwordEncoder(passwordEncoder());
//         return auth.build();
//     }
    
//     @Bean
//     public WebSecurityCustomizer webSecurityCustomizer() {
//         return (web) -> web.ignoring().requestMatchers("/resources/**", "/static/**", "/css/**", "/js/**", "/images/**");
//     }

//     @Bean
//     public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//         http
//             .authorizeHttpRequests(authorize -> authorize
//                 .requestMatchers("/home", "/login").authenticated()
//                 .anyRequest().permitAll())
//             .formLogin(formLogin -> formLogin
//                 .loginPage("/login")
//                 .defaultSuccessUrl("/loginSuccess", true)
//                 .failureUrl("/loginFailure")
//                 .permitAll())
//             .logout(logout -> logout
//                 .permitAll())
//             .oauth2Login(oauth2Login -> oauth2Login
//                 .loginPage("/login")
//                 .defaultSuccessUrl("/loginSuccess")
//                 .failureUrl("/loginFailure")
//                 .clientRegistrationRepository(clientRegistrationRepository)); // OAuth2 클라이언트 설정 추가
//         return http.build();
//     }



//     @Bean
//     public RestTemplate restTemplate() {
//         return new RestTemplate();
//     }
    


// }
package com.goldensnitch.qudditch.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.client.RestTemplate;

import com.goldensnitch.qudditch.jwt.JwtTokenFilter;
import com.goldensnitch.qudditch.service.CustomUserDetailsService;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // UserDetailsService 및 ClientRegistrationRepository 주입
    private final CustomUserDetailsService userDetailsService;
    
    private final ClientRegistrationRepository clientRegistrationRepository;

    private final JwtTokenFilter jwtTokenFilter;

    public SecurityConfig(CustomUserDetailsService userDetailsService, ClientRegistrationRepository clientRegistrationRepository, JwtTokenFilter jwtTokenFilter) {
        this.userDetailsService = userDetailsService;
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.jwtTokenFilter = jwtTokenFilter;
    }

    // PasswordEncoder 빈 정의
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 스프링 시큐리티가 제공하는 기본 구성을 사용하여 AuthenticationManager를 설정합니다.
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
            .passwordEncoder(passwordEncoder());

    }
    
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
    }



    // SecurityFilterChain 빈 정의
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf.disable())
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/public/**").permitAll()  // 누구나 접근 가능한 공개 경로
            .requestMatchers("/user/**").hasRole("USER")    // 일반 유저만 접근 가능
            .requestMatchers("/store/**").hasRole("STORE")  // 점주만 접근 가능
            .requestMatchers("/admin/**").hasRole("ADMIN")  // 관리자만 접근 가능
            .anyRequest().authenticated())  // 나머지 경로는 인증된 사용자만 접근 가능
            // 4. 사용자 권한에 따른 UI 구성
            // 일반 유저: 기본적인 서비스 화면.
            // 점주: 매출 그래프, 매장 관리 탭 추가. (데이터베이스 또는 서비스 레이어에서 권한에 따른 데이터 접근 로직을 구현 EX.점주는 자신의 매장에 대한정보만 조회할 수 있어야한다.)
            // 관리자: 발주 관리, 시스템 관리 탭 추가.
        .oauth2Login(oauth -> oauth
            .loginPage("/login")
            .defaultSuccessUrl("/loginSuccess")
            .failureUrl("/loginFailure")
            .clientRegistrationRepository(clientRegistrationRepository))
        .formLogin(form -> form
            //... 폼 로그인 관련 설정
            .loginPage("/login")
            .defaultSuccessUrl("/loginSuccess", true)  // 로그인 성공 시 리다이렉트될 URL
            .failureUrl("/loginFailure")  // 로그인 실패 시 리다이렉트될 URL
            .permitAll())
        // 로그아웃 설정이 리다이렉트 루프에 영향을 주지 않도록 주의
        .logout(logout -> logout
            .logoutSuccessUrl("/login")  // 로그아웃 성공 시 로그인 페이지로 이동
            .deleteCookies("JSESSIONID") // 로그아웃 시 쿠키 삭제
            .permitAll())
        // ... 기타 설정
        .and()
        .exceptionHandling().defaultAuthenticationEntryPointFor(
            new LoginUrlAuthenticationEntryPoint("/home"),
            new AntPathRequestMatcher("/login"));
        
        // JWT 필터 설정이 필요하다면 여기에 추가
        http.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }



    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    


}
