package by.innowise.internship.security.filter;

import by.innowise.internship.security.dto.TokenDto;
import by.innowise.internship.security.dto.UserHolder;
import by.innowise.internship.security.util.JwtHandler;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

@RequiredArgsConstructor
@Slf4j
public class JwtFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String JWT_AUTH_HEADER_PREFIX = "Bearer ";
    private final JwtHandler jwtHandler;
    private final AntPathMatcher matcher = new AntPathMatcher();
    @Setter
    private List<String> whitelistPaths = Collections.emptyList();

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getServletPath();
        boolean isFiltered = whitelistPaths.stream().anyMatch(urlPattern -> matcher.match(urlPattern, path));
        log.info("Filtering path: {}, method:{},  shouldNotFilter: {}", path, request.getMethod(), isFiltered);
        return isFiltered;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader(AUTHORIZATION_HEADER);

        if (headerIsInvalid(header)) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.substring(JWT_AUTH_HEADER_PREFIX.length());

        if (tokenIsNotValid(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        TokenDto tokenDto = jwtHandler.parseToken(token);

        Authentication auth = getAuthentication(tokenDto);

        SecurityContextHolder.getContext().setAuthentication(auth);

        filterChain.doFilter(request, response);
    }

    private boolean tokenIsNotValid(String token) {
        return !jwtHandler.isValid(token);
    }

    private boolean headerIsInvalid(String header) {
        return !StringUtils.hasText(header) || !header.startsWith(JWT_AUTH_HEADER_PREFIX);
    }

    private Authentication getAuthentication(TokenDto tokenDto) {
        return new UsernamePasswordAuthenticationToken(new UserHolder(tokenDto.crossServiceUserId(), tokenDto.email()),
                                                       null,
                                                       tokenDto.roles());
    }
}
