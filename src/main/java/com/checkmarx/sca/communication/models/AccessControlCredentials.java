package com.checkmarx.sca.communication.models;

import org.jetbrains.annotations.NotNull;

public class AccessControlCredentials {
    private final String _username;
    private final String _password;
    private final String _tenant;

    public AccessControlCredentials(@NotNull String username, @NotNull String password, @NotNull String tenant) {
        this._username = username;
        this._password = password;
        this._tenant = tenant;
    }

    public String getUsername() {
        return this._username;
    }

    public String getPassword() {
        return this._password;
    }

    public String getTenant() {
        return this._tenant;
    }
}
