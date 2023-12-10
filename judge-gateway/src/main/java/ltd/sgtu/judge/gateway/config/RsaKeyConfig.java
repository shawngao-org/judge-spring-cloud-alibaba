package ltd.sgtu.judge.gateway.config;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "rsa")
public class RsaKeyConfig {

    @Value("private-key")
    private String privateKey;
    @Value("public-key")
    private String publicKey;
}
