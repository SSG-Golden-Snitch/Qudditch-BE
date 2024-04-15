// 토큰사용법
// 토큰 발급: 사용자가 로그인을 성공하면 서버는 JWT 토큰을 발급하고,
// 이 토큰은 클라이언트(예: 웹 브라우저나 모바일 앱)에 반환됩니다.

// 토큰 사용: 클라이언트는 서버에 요청을 보낼 때, 이 토큰을 HTTP 요청 헤더에 포함시켜야 합니다. 
// 일반적으로 Authorization 헤더에 Bearer 스키마를 사용하여 토큰을 추가합니다.
// 예를 들어, JWT 토큰이 abc123이라면, 요청 헤더에 다음과 같이 포함시킵니다:
// Authorization: Bearer abc123

// 토큰 검증: 서버는 요청을 받을 때마다 Authorization 헤더에서 토큰을 추출하고, 이 토큰의 유효
// 성을 검증합니다. 토큰이 유효하면 요청이 처리되고, 유효하지 않으면 에러를 반환합니다.
package com.goldensnitch.qudditch.jwt;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;


@Component
public class JwtTokenProvider {
    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);
    @Value("${jwt.secret}")
    private String JWT_SECRET;

    @Value("${jwt.expirationInMs}")
    private int JWT_EXPIRATION_IN_MS;

    // Authentication 객체를 받아서 토큰을 생성하는 메서드로 수정합니다.
public String generateToken(Authentication authentication) {
    UserDetails userDetails = (UserDetails) authentication.getPrincipal();
    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + JWT_EXPIRATION_IN_MS);

    String authorities = authentication.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors.joining(","));

    return Jwts.builder()
        .setSubject(userDetails.getUsername())
        .claim("roles", authorities)
        .claim("name", userDetails.getUsername())
        .setIssuedAt(now)
        .setExpiration(expiryDate)
        .signWith(SignatureAlgorithm.HS256, JWT_SECRET)
        .compact();
}

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser()
                // .verifyWith(secretKey)
                .setSigningKey(JWT_SECRET).build().parseSignedClaims(authToken);
            return true;
        } catch (ExpiredJwtException e) {
            logger.error("인증 토큰이 만료되었습니다.", e);
        } catch (UnsupportedJwtException e) {
            logger.error("지원하지 않는 인증 토큰입니다.", e);
        } catch (MalformedJwtException e) {
            logger.error("잘못된 인증 토큰 형식입니다", e);
        } catch (SecurityException e) {
            logger.error("인증 토큰의 서명이 유효하지 않습니다.", e);
        } catch (IllegalArgumentException e) {
            logger.error("인증 토큰의 compact한 형태가 유효하지 않습니다.", e);
        }

        return false;
    }

    public Claims extractClaims(String token) {
        return Jwts.parser().setSigningKey(JWT_SECRET)
            // v.decryptWith(sKey)
            .build().parseSignedClaims(token).getPayload();
    }

    public List<SimpleGrantedAuthority> getAuthorities(String token) {
        Claims claims = extractClaims(token);
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();

        String roles = claims.get("roles", String.class);
        if (roles != null && !roles.isEmpty()) {
            for (String role : roles.split(",")) {
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            }
        }

        return authorities;
    }
}
