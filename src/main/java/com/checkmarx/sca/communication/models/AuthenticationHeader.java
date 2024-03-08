package com.checkmarx.sca.communication.models;

public class AuthenticationHeader {
    private final Object _key;
    private final Object _value;

    public AuthenticationHeader(Object key, Object value) {
        this._key = key;
        this._value = value;
    }

    public Object getKey() {
        return this._key;
    }

    public Object getValue() {
        return this._value;
    }
}
