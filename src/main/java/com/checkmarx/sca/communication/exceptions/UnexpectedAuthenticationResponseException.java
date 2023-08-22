package com.checkmarx.sca.communication.exceptions;

public class UnexpectedAuthenticationResponseException extends RuntimeException {
    public UnexpectedAuthenticationResponseException(String message) {
        super(String.format("Received an unexpected response from the authentication server (Response: %s)", message));
    }
}
