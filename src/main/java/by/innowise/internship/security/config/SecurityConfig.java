package by.innowise.internship.security.config;

import by.innowise.internship.security.filter.JwtFilter;
import by.innowise.internship.security.filter.JwtFilterConfigurer;
import by.innowise.internship.security.util.JwtHandler;
import by.innowise.internship.security.util.JwtHandlerImpl;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import java.util.Base64;

@Configuration
@EnableConfigurationProperties(JwtSecurityProperties.class)
@ConditionalOnBooleanProperty(
        prefix = "application.security",
        name = "enabled"
)
public class SecurityConfig {

    @Bean
    public SecretKey secretKey(JwtSecurityProperties jwtProps) {
        String secretKeyBase64Url = jwtProps.getSecretKey();
        return Keys.hmacShaKeyFor(Base64.getUrlDecoder().decode(secretKeyBase64Url));
    }

    @Bean
    public JwtParser jwtParser(SecretKey secretKey) {
        return Jwts.parser()
                   .verifyWith(secretKey)
                   .clockSkewSeconds(120)
                   .build();
    }

    @Bean
    public JwtHandler jwtHandler(JwtParser jwtParser) {
        return new JwtHandlerImpl(jwtParser);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtFilter jwtFilter(JwtHandler jwtHandler, ObjectProvider<JwtFilterConfigurer> configurers) {
        JwtFilter filter = new JwtFilter(jwtHandler);
        configurers.orderedStream().forEach(configurer -> configurer.configure(filter));
        return filter;
    }

}
