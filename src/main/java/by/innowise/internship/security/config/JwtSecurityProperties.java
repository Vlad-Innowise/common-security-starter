package by.innowise.internship.security.config;

import by.innowise.internship.security.exception.MissingTokenTypeTtlException;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;

@Data
@NoArgsConstructor
@ConfigurationProperties(prefix = "application.security")
public class JwtSecurityProperties {

    /**
     * enables to use a Security Starter
     */
    private boolean enabled;

    /**
     * @return the Base64 encrypted secret key for token signing and verification
     */
    private String secretKey;

    /**
     * token time-to-live in minutes
     */
    private Map<String, Duration> ttl;

    /**
     * issuer name
     */
    private String issuer;

    public Duration getTtlForType(String type) {
        return Optional.ofNullable(ttl.get(type))
                       .orElseThrow(() -> new MissingTokenTypeTtlException(type));
    }

}
