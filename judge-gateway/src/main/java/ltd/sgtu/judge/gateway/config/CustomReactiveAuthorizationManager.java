package ltd.sgtu.judge.gateway.config;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Slf4j
@Component
public class CustomReactiveAuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {

    private static final Map<String, String> AUTH_MAP = new HashMap<>();

    @PostConstruct
    public void initAuthMap() {
        AUTH_MAP.put("/api/router/findAll", "all");
    }

    @Override
    public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, AuthorizationContext object) {
        ServerWebExchange exchange = object.getExchange();
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        String author = AUTH_MAP.get(path);
        log.info("Path: [{}], Permission: [{}]", path, author);
        if (request.getMethod().equals(HttpMethod.OPTIONS)) {
            return Mono.just(new AuthorizationDecision(true));
        }
        if (!StringUtils.hasText(author)) {
            return Mono.just(new AuthorizationDecision(false));
        }
        return authentication.filter(Authentication::isAuthenticated)
                .filter(a -> a instanceof JwtAuthenticationToken)
                .cast(JwtAuthenticationToken.class)
                .doOnNext(t -> {
                    log.info(t.getToken().getHeaders().toString());
                    log.info(t.getTokenAttributes().toString());
                })
                .flatMapIterable(AbstractAuthenticationToken::getAuthorities)
                .map(GrantedAuthority::getAuthority)
                .any(a -> Objects.equals(a, author))
                .map(AuthorizationDecision::new)
                .defaultIfEmpty(new AuthorizationDecision(false));
    }
}
