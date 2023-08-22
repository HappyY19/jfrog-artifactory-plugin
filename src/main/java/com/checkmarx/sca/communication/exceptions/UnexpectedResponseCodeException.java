package com.checkmarx.sca.communication.exceptions;

public class UnexpectedResponseCodeException extends RuntimeException {
    public final int StatusCode;

    public UnexpectedResponseCodeException(int statusCode) {
        super(String.format("Received an unexpected response code from the Sca API (Code: %d)", statusCode));
        this.StatusCode = statusCode;
    }
}
