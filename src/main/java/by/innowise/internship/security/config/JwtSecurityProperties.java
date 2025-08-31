package by.innowise.internship.security.config;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@NoArgsConstructor
@ConfigurationProperties(prefix = "application.security")
public class JwtSecurityProperties {

    /**
     * enables to use a Security Starter
     * */
    private boolean enabled;

    /**
     * @return the Base64 encrypted secret key for token signing and verification
     * */
    private String secretKey;

    /**
     * token time-to-live in minutes
     * */
    private int tokenTtlInMinutes = 15;

    /**
     * issuer name
     * */
    private String issuer;

}
