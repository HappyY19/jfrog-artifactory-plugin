package com.checkmarx.sca.communication.models;

import com.google.gson.annotations.SerializedName;

import java.time.Duration;
import java.time.Instant;

public class AccessControlToken {
    @SerializedName("access_token")
    private String _accessToken;
    @SerializedName("token_type")
    private String _tokenType;
    @SerializedName("expires_in")
    private int _expiresIn;
    private final transient Instant _requestDate = Instant.now();

    public AccessControlToken() {
    }

    public String getAccessToken() {
        return this._accessToken;
    }

    public String getTokenType() {
        return this._tokenType;
    }

    public double ExpiresIn() {
        Instant utcNow = Instant.now();
        Instant expirationDate = this._requestDate.plusSeconds((long) this._expiresIn);
        return (double) Duration.between(utcNow, expirationDate).toSeconds();
    }

    public boolean isActive() {
        return this.ExpiresIn() > 0.0;
    }

    public boolean isBearerToken() {
        return this._accessToken != null
                && this._tokenType != null
                && this._tokenType.equalsIgnoreCase("Bearer")
                && !this._accessToken.trim().isEmpty();
    }
}
