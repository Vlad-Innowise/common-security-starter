package by.innowise.internship.security.config;

import by.innowise.internship.security.filter.JwtFilter;
import by.innowise.internship.security.util.JwtHandler;
import by.innowise.internship.security.util.JwtHandlerImpl;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Configuration
@EnableConfigurationProperties(JwtSecurityProperties.class)
@ConditionalOnBooleanProperty(
        prefix = "application.security",
        name = "enabled"
)
public class SecurityConfig {

    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecretKey secretKey(JwtSecurityProperties jwtProps) {
        String secretKey = jwtProps.getSecretKey();
        return Keys.hmacShaKeyFor(Base64.getDecoder().decode(secretKey.getBytes(StandardCharsets.UTF_8)));
    }

    @Bean
    public JwtParser jwtParser(SecretKey secretKey) {
        return Jwts.parser()
                   .verifyWith(secretKey)
                   .build();
    }

    @Bean
    public JwtHandler jwtHandler(JwtParser jwtParser) {
        return new JwtHandlerImpl(jwtParser);
    }

    @Bean
    public JwtFilter jwtFilter(JwtHandler jwtHandler) {
        return new JwtFilter(jwtHandler);
    }

}
