package by.innowise.internship.security.exception;

public class MissingTokenTypeTtlException extends RuntimeException {

    public MissingTokenTypeTtlException(String type) {
        super("Haven't found a ttl property for the type [%s]".formatted(type));
    }
}
