package ltd.sgtu.judge.gateway.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Slf4j
public class CustomServerAccessDeniedHandler implements ServerAccessDeniedHandler {
    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {
        ServerHttpRequest request = exchange.getRequest();
        return exchange.getPrincipal()
                .doOnNext(p -> log.error("User: [{}] don't have permission for [{}]",
                        p.getName(), request.getURI()))
                .flatMap(p -> {
                    ServerHttpResponse r = exchange.getResponse();
                    r.setStatusCode(HttpStatus.FORBIDDEN);
                    String body = "{\"msg\": \"You don't have permission access this.\"}";
                    DataBuffer buffer = r.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
                    return r.writeWith(Mono.just(buffer))
                            .doOnError(e -> DataBufferUtils.release(buffer));
                });
    }
}
