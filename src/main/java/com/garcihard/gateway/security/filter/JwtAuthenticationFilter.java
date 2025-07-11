package com.garcihard.gateway.security.filter;

import com.garcihard.gateway.security.util.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;


@Order(-1)
@Component
public class JwtAuthenticationFilter implements GlobalFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    static final String BEARER_PREFIX = "Bearer";

    private final JwtUtil jwtUtil;

    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);

        boolean isPublic = false;
        if (route != null) {
            isPublic = (boolean) route.getMetadata().getOrDefault("is-public", false);
        }

        if (isPublic) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX + " ")) {
            log.warn("Missing or invalid Authorization header for request: {}", exchange.getRequest().getURI());
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing or invalid Authorization header"));
        }

        String token = authHeader.substring(BEARER_PREFIX.length() + 1);
        try {
            Claims claims = jwtUtil.validateAndParseClaims(token);
            // Mutamos la petición original para crear una NUEVA instancia con el header nuevo.
            ServerHttpRequest mutatedRequest = exchange.getRequest()
                    .mutate()
                    .header("X-User-Id", claims.getSubject()).build();
            // Creamos un NUEVO ServerWebExchange con la petición mutada.
            ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();
            return chain.filter(mutatedExchange);
        } catch (ExpiredJwtException e) {
            log.warn("Expired JWT token for request: {}", exchange.getRequest().getURI());
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token has expired."));
        } catch (SignatureException e) {
            log.warn("Invalid JWT signature for request: {}", exchange.getRequest().getURI());
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token signature."));
        } catch (MalformedJwtException e) {
            log.warn("Malformed JWT token for request: {}", exchange.getRequest().getURI());
            return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "Malformed token."));
        } catch (UnsupportedJwtException e) {
            log.warn("Unsupported JWT token for request: {}", exchange.getRequest().getURI());
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unsupported token."));
        } catch (Exception e) {
            log.error("Unexpected error validating JWT for request: {}", exchange.getRequest().getURI(), e);
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token."));
        }
    }
}
