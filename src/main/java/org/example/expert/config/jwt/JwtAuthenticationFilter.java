package org.example.expert.config.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.domain.common.dto.AuthUser;
import org.example.expert.domain.user.enums.UserRole;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer";
    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain
    ) throws ServletException, IOException {

        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);

        if (bearerToken == null || !StringUtils.startsWithIgnoreCase(bearerToken, BEARER_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        String jwt = jwtUtil.substringToken(bearerToken);

        try {
            Claims claims = jwtUtil.extractClaims(jwt);

            if (claims == null) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "잘못된 JWT 토큰입니다.");
                return;
            }

            long userId = Long.parseLong(claims.getSubject());
            String email = claims.get("email", String.class);
            String userRole = claims.get("userRole", String.class);
            String nickname = claims.get("nickname", String.class);

            AuthUser authUser = new AuthUser(userId, email, UserRole.of(userRole), nickname);
            JwtAuthenticationToken authentication = new JwtAuthenticationToken(authUser);

            SecurityContextHolder.getContext().setAuthentication(authentication);

            Authentication authentication1 = SecurityContextHolder.getContext().getAuthentication();
            log.debug("get from context: {}", authentication1);

            chain.doFilter(request, response);
        } catch (SecurityException | MalformedJwtException e) {
            log.error("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.", e);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "유효하지 않는 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token, 만료된 JWT token 입니다.", e);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.", e);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "지원되지 않는 JWT 토큰입니다.");
        } catch (Exception e) {
            log.error("Internal server error", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }

    }

    //    @Override
//    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
//        HttpServletRequest httpRequest = (HttpServletRequest) request;
//        HttpServletResponse httpResponse = (HttpServletResponse) response;
//
//        String url = httpRequest.getRequestURI();
//
//        if (url.startsWith("/auth")) {
//            chain.doFilter(request, response);
//            return;
//        }
//
//        String bearerJwt = httpRequest.getHeader("Authorization");
//
//        if (bearerJwt == null) {
//            // 토큰이 없는 경우 400을 반환합니다.
//            httpResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "JWT 토큰이 필요합니다.");
//            return;
//        }
//
//        String jwt = jwtUtil.substringToken(bearerJwt);
//
//        try {
//            // JWT 유효성 검사와 claims 추출
//            Claims claims = jwtUtil.extractClaims(jwt);
//            if (claims == null) {
//                httpResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "잘못된 JWT 토큰입니다.");
//                return;
//            }
//
//            UserRole userRole = UserRole.valueOf(claims.get("userRole", String.class));
//
//            httpRequest.setAttribute("userId", Long.parseLong(claims.getSubject()));
//            httpRequest.setAttribute("email", claims.get("email"));
//            httpRequest.setAttribute("userRole", claims.get("userRole"));
//            httpRequest.setAttribute("nickname", claims.get("nickname"));
//
//            if (url.startsWith("/admin")) {
//                // 관리자 권한이 없는 경우 403을 반환합니다.
//                if (!UserRole.ADMIN.equals(userRole)) {
//                    httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "관리자 권한이 없습니다.");
//                    return;
//                }
//                chain.doFilter(request, response);
//                return;
//            }
//
//            chain.doFilter(request, response);
//        } catch (SecurityException | MalformedJwtException e) {
//            log.error("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.", e);
//            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "유효하지 않는 JWT 서명입니다.");
//        } catch (ExpiredJwtException e) {
//            log.error("Expired JWT token, 만료된 JWT token 입니다.", e);
//            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "만료된 JWT 토큰입니다.");
//        } catch (UnsupportedJwtException e) {
//            log.error("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.", e);
//            httpResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "지원되지 않는 JWT 토큰입니다.");
//        } catch (Exception e) {
//            log.error("Internal server error", e);
//            httpResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
//        }
//    }

}
