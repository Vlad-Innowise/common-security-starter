package by.innowise.internship.security.util;

import by.innowise.internship.security.dto.TokenDto;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class JwtHandlerImpl implements JwtHandler {

    private final JwtParser jwtParser;

    @Override
    public TokenDto parseToken(String token) {
        Claims claims = jwtParser.parseSignedClaims(token)
                                 .getPayload();

        List<?> rawRoles = claims.get(JwtConstants.JWT_ROLE_CLAIM_NAME, List.class);
        List<SimpleGrantedAuthority> roles = rawRoles.stream()
                                                     .filter(String.class::isInstance)
                                                     .map(String.class::cast)
                                                     .map(SimpleGrantedAuthority::new)
                                                     .toList();
        return new TokenDto(
                Long.parseLong(claims.getSubject()),
                claims.get(JwtConstants.JWT_EMAIL_CLAIM_NAME, String.class),
                roles);
    }

    @Override
    public boolean isValid(String token) {
        try {
            jwtParser.parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.error("The provided token is invalid or expired: {}", token);
            return false;
        }
    }
}
