package com.goldensnitch.qudditch.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.goldensnitch.qudditch.jwt.JwtTokenProvider;

@RestController
public class OAuth2LoginController {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @GetMapping("/login/oauth2/code/{provider}")
public ResponseEntity<?> oauth2Login(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient,
                                    Authentication authentication) {
    // Create JWT token from authentication object
    String jwtToken = jwtTokenProvider.generateToken(authentication);

    HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.SET_COOKIE, "jwt=" + jwtToken + "; HttpOnly; Path=/; Max-Age=7200");
    return new ResponseEntity<>(headers, HttpStatus.FOUND);
}
}