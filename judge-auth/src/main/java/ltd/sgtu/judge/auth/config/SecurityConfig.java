package ltd.sgtu.judge.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    public static final String CUSTOM_LOGIN_PAGE_URI = "/login";
    public static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";

    @Bean
    public SecurityFilterChain httpSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
         httpSecurity
            .authorizeHttpRequests((authorize) ->
                    authorize.anyRequest().authenticated()
            )
            // Form login handles the redirect to the login page from the
            // authorization server filter chain
            .formLogin(Customizer.withDefaults())
                 .formLogin(f -> f.loginPage(CUSTOM_LOGIN_PAGE_URI).permitAll())
                 .csrf(c -> c.csrfTokenRepository(new CookieCsrfTokenRepository()));
        return httpSecurity.build();
    }
}
