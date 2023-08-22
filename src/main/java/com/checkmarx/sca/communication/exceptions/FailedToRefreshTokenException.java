package com.checkmarx.sca.communication.exceptions;

public class FailedToRefreshTokenException extends RuntimeException {
    public FailedToRefreshTokenException() {
        super("An unexpected error occurred while refreshing the token");
    }
}
