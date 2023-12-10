package ltd.sgtu.judge.gateway.config;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

@Configuration
@EnableWebFluxSecurity
public class ResourceServerConfig {

    private RsaKeyConfig rsaKeyConfig;

    @Autowired
    public void setRsaKeyConfig(RsaKeyConfig rsaKeyConfig) {
        this.rsaKeyConfig = rsaKeyConfig;
    }

    private CustomReactiveAuthorizationManager customReactiveAuthorizationManager;

    @Autowired
    public void setCustomReactiveAuthorizationManager(CustomReactiveAuthorizationManager customReactiveAuthorizationManager) {
        this.customReactiveAuthorizationManager = customReactiveAuthorizationManager;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity httpSecurity)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return httpSecurity.oauth2ResourceServer().jwt()
            .jwtAuthenticationConverter(jwtConvert())
            .jwtDecoder(jwtDecoder())
            .and()
            .accessDeniedHandler(new CustomServerAccessDeniedHandler())
            .authenticationEntryPoint(new CustomAuthenticationEntryPoint())
            .bearerTokenConverter(new ServerBearerTokenAuthenticationConverter())
            .and()
            .authorizeExchange()
//            .pathMatchers("/api/router/admin")
//            .permitAll()
            .anyExchange().access(customReactiveAuthorizationManager)
            .and()
            .exceptionHandling()
            .accessDeniedHandler(new CustomServerAccessDeniedHandler())
            .authenticationEntryPoint(new CustomAuthenticationEntryPoint())
            .and()
            .csrf().disable()
            .addFilterAfter(new TokenTransferFilter(),
                    SecurityWebFiltersOrder.AUTHENTICATION)
            .build();
    }

    public Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtConvert() {
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");
        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("scope");
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setPrincipalClaimName("sub");
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        return new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);
    }

    public ReactiveJwtDecoder jwtDecoder() throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        byte[] pubKeyBytes = Base64.decodeBase64(rsaKeyConfig.getPublicKey());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
        return NimbusReactiveJwtDecoder.withPublicKey(rsaPublicKey)
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();
    }
}
