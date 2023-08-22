package com.checkmarx.sca.communication.exceptions;

public class AuthenticationFailedException extends RuntimeException {
    public AuthenticationFailedException(int statusCode) {
        super(String.format("Failed to authenticate client with authentication server (Code %d)", statusCode));
    }
}
