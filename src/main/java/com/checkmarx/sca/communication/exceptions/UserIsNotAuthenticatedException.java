package com.checkmarx.sca.communication.exceptions;

public class UserIsNotAuthenticatedException extends RuntimeException {
    public UserIsNotAuthenticatedException() {
        super("The user is not yet authenticated.");
    }
}
