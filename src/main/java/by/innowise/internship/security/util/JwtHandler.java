package by.innowise.internship.security.util;

import by.innowise.internship.security.dto.TokenDto;

public interface JwtHandler {

    boolean isValid(String token);

    TokenDto parseToken(String token);
}
