package com.goldensnitch.qudditch.jwt;

import com.goldensnitch.qudditch.service.CustomUserDetailsService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    // 토큰에서 권한을 추출하여 Security Context에 저장하는 메소드
    // @Override
    // protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
    //         throws ServletException, IOException {
    //     try {
    //         if (!isLoginRequest(request)) {
    //             String token = getTokenFromRequest(request);
    //             if (token != null && jwtTokenProvider.validateToken(token)) {
    //                 Claims claims = jwtTokenProvider.extractClaims(token);
    //                 UsernamePasswordAuthenticationToken authentication =
    //                     new UsernamePasswordAuthenticationToken(claims.getSubject(), null, jwtTokenProvider.getAuthorities(token));
    //                 authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
    //                 SecurityContextHolder.getContext().setAuthentication(authentication);
    //             }
    //         }

    //     } catch (ExpiredJwtException e) {
    //         response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token has expired");
    //     } catch (MalformedJwtException e) {
    //         response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid JWT token format");
    //     } catch (UnsupportedJwtException e) {
    //         response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unsupported JWT token");
    //     } catch (JwtException e) {
    //         response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
    //     }
    //     filterChain.doFilter(request, response);
    // }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {

        String token = getTokenFromRequest(request);
        if (token != null && jwtTokenProvider.validateToken(token)) {
            Claims claims = jwtTokenProvider.extractClaims(token);
            //토큰으로부터 이메일 추출
            String email = claims.getSubject();
            //Collection<? extends GrantedAuthority> authorities = jwtTokenProvider.getAuthorities(token);

            // UserDetailsService를 사용하여 ExtendedUserDetails를 로드한다.
            UserDetails userDetails = customUserDetailsService.loadUserByUsername(email);
            UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

            // UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
            //     claims.getSubject(), null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
    }

    private boolean isLoginRequest(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.equals("/login") || path.equals("/store/login") || path.startsWith("/social-login");
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
