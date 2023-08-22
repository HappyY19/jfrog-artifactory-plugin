package com.checkmarx.sca.communication.models;

public class AuthenticationHeader<K, V> {
    private final K _key;
    private final V _value;

    public AuthenticationHeader(K key, V value) {
        this._key = key;
        this._value = value;
    }

    public K getKey() {
        return this._key;
    }

    public V getValue() {
        return this._value;
    }
}
