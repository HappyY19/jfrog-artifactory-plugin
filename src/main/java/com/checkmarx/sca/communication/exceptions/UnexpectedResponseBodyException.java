package com.checkmarx.sca.communication.exceptions;

public class UnexpectedResponseBodyException extends RuntimeException {
    public UnexpectedResponseBodyException(String message) {
        super(String.format("Received an unexpected response from the Sca API (Response: %s)", message));
    }
}
