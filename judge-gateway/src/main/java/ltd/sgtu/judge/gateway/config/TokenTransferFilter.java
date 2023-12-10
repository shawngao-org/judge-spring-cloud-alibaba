package ltd.sgtu.judge.gateway.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.annotation.Nonnull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Slf4j
public class TokenTransferFilter implements WebFilter {

    private static final ObjectMapper om = new ObjectMapper();

    static {
        om.registerModule(new Jdk8Module());
        om.registerModule(new JavaTimeModule());
    }

    @Nonnull
    @Override
    public Mono<Void> filter(@Nonnull ServerWebExchange exchange, @Nonnull WebFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .cast(JwtAuthenticationToken.class)
                .flatMap(a -> {
                    ServerHttpRequest request = exchange.getRequest();
                    request = request.mutate()
                            .header("tokenInfo", toJsonStr(a.getPrincipal()))
                            .build();
                    ServerWebExchange e = exchange.mutate().request(request).build();
                    return chain.filter(e);
                })
                .switchIfEmpty(Mono.defer(() -> chain.filter(exchange)))
                .onErrorResume(e -> chain.filter(exchange));
    }

    public String toJsonStr(Object o) {
        try {
            return (new ObjectMapper()).writeValueAsString(o);
        } catch (JsonProcessingException e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }
}
