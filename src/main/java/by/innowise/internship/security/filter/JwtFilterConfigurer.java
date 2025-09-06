package by.innowise.internship.security.filter;

@FunctionalInterface
public interface JwtFilterConfigurer {

    void configure(JwtFilter filter);
}
