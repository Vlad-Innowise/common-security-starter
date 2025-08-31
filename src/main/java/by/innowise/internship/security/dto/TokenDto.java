package by.innowise.internship.security.dto;

import org.springframework.security.core.GrantedAuthority;

import java.util.List;

public record TokenDto(
        Long crossServiceUserId,
        String email,
        List<? extends GrantedAuthority> roles
) {
}
