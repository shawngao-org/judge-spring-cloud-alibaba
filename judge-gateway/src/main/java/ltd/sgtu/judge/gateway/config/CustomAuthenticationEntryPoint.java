package ltd.sgtu.judge.gateway.config;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

public class CustomAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {
    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        return Mono.defer(() -> Mono.just(exchange.getResponse()))
                .flatMap(r -> {
                    r.setStatusCode(HttpStatus.UNAUTHORIZED);
                    String body = "{\"msg\": \"Invalid token.\"}";
                    DataBuffer buffer = r.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
                    return r.writeWith(Mono.just(buffer))
                            .doOnError(e -> DataBufferUtils.release(buffer));
                });
    }
}
